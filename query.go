package wmi

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"iter"
	"strings"
)

const defaultNamespace = "//./root/cimv2"

// Query describes a WQL query to execute against a WMI namespace.
type Query struct {
	Query     string
	Namespace string
	Language  string
	Flags     uint32
	Timeout   uint32

	SkipOptimize  bool
	ResultOptions ResultOptions

	flagsSet   bool
	timeoutSet bool
}

// QueryOption configures a [Query].
type QueryOption func(*Query)

// WithNamespace overrides the default WMI namespace for a query.
func WithNamespace(namespace string) QueryOption {
	return func(q *Query) {
		q.Namespace = normalizeNamespace(namespace)
	}
}

// WithLanguage overrides the query language. The default is WQL.
func WithLanguage(language string) QueryOption {
	return func(q *Query) {
		q.Language = language
	}
}

// WithFlags overrides the WBEM query flags.
func WithFlags(flags uint32) QueryOption {
	return func(q *Query) {
		q.Flags = flags
		q.flagsSet = true
	}
}

// WithTimeout sets the default per-row fetch timeout in milliseconds.
func WithTimeout(timeout uint32) QueryOption {
	return func(q *Query) {
		q.Timeout = timeout
		q.timeoutSet = true
	}
}

// WithSkipOptimize disables the smart-enum optimization when set to true.
func WithSkipOptimize(skip bool) QueryOption {
	return func(q *Query) {
		q.SkipOptimize = skip
	}
}

// WithResultOptions configures property shaping for query results.
func WithResultOptions(options ResultOptions) QueryOption {
	return func(q *Query) {
		q.ResultOptions = options
	}
}

// ResultOptions controls which properties are included in query results.
type ResultOptions struct {
	IgnoreDefaults bool
	IgnoreMissing  bool
	LoadQualifiers bool
}

// QContext holds the state for an in-progress WMI query.
type QContext struct {
	query         Query
	conn          *connection
	service       *service
	flags         uint32
	timeout       uint32
	skipOptimize  bool
	classParts    map[string]*classPart
	interfaceIPID string
	proxyGUID     []byte
	smart         bool
	resultOptions ResultOptions
}

// NewQuery creates a Query with default namespace and language.
func NewQuery(query string, opts ...QueryOption) Query {
	q := Query{
		Query:      query,
		Namespace:  defaultNamespace,
		Language:   "WQL",
		Flags:      DefaultQueryFlags(),
		Timeout:    60,
		flagsSet:   true,
		timeoutSet: true,
	}
	for _, opt := range opts {
		opt(&q)
	}
	return q
}

// DefaultResultOptions returns the default ResultOptions.
func DefaultResultOptions() ResultOptions {
	return ResultOptions{}
}

// DefaultQueryFlags returns the default WBEM query flags.
func DefaultQueryFlags() uint32 {
	return WBEMFlagReturnImmediately | WBEMFlagForwardOnly
}

func normalizeNamespace(namespace string) string {
	namespace = strings.TrimSpace(namespace)
	switch {
	case namespace == "":
		return defaultNamespace
	case strings.HasPrefix(namespace, "//"):
		return namespace
	default:
		return "//./" + namespace
	}
}

func (q Query) context(conn *connection, svc *service) *QContext {
	q.Namespace = normalizeNamespace(q.Namespace)
	if q.Language == "" {
		q.Language = "WQL"
	}
	if !q.flagsSet {
		q.Flags = DefaultQueryFlags()
	}
	if !q.timeoutSet {
		q.Timeout = 60
	}
	return &QContext{
		query:         q,
		conn:          conn,
		service:       svc,
		flags:         q.Flags,
		timeout:       q.Timeout,
		skipOptimize:  q.SkipOptimize,
		classParts:    make(map[string]*classPart),
		resultOptions: q.ResultOptions,
	}
}

// run starts the query, calls fn, and closes the query on return.
func (q *QContext) run(ctx context.Context, fn func(*QContext) error) (err error) {
	if fn == nil {
		return errors.New("query context callback is nil")
	}
	if err := q.start(ctx); err != nil {
		return err
	}
	defer func() {
		if closeErr := q.close(ctx); closeErr != nil {
			if err != nil {
				err = errors.Join(err, closeErr)
			} else {
				err = closeErr
			}
		}
	}()
	return fn(q)
}

// results iterates over all result rows, calling yield for each one.
func (q *QContext) results(
	ctx context.Context,
	yield func(map[string]*Property) error,
) error {
	if yield == nil {
		return errors.New("query results callback is nil")
	}
	for {
		props, err := q.next(ctx)
		if err != nil {
			if errors.Is(err, &Error{Code: wbemSFalse}) {
				return nil
			}
			return err
		}
		if err := yield(props); err != nil {
			return err
		}
	}
}

// start begins the WMI query and prepares the result stream.
func (q *QContext) start(ctx context.Context) error {
	debugf("query start namespace=%s skip_optimize=%v flags=0x%08x", q.query.Namespace, q.skipOptimize, q.flags)
	if q.conn.namespace != q.query.Namespace {
		if err := q.conn.loginNTLM(ctx, q.service, q.query.Namespace); err != nil {
			return err
		}
	}

	lang := q.query.Language
	queryText := q.query.Query
	pdu := bytes.NewBuffer(nil)
	pdu.Write(orpcthis(0))
	pdu.Write(wordStr(&lang))
	pdu.Write(wordStr(&queryText))
	_ = binary.Write(pdu, binary.LittleEndian, q.flags)
	pdu.Write(getNull())

	req := newRPCRequest(20, q.service.proto.currentIPID)
	req.setAppData(pdu.Bytes())
	wire, err := req.signData(q.service.proto)
	if err != nil {
		return err
	}
	reply, err := q.service.proto.roundTrip(ctx, wire)
	if err != nil {
		return err
	}
	msg, err := q.service.proto.responseMessage(reply.fragments)
	if err != nil {
		return err
	}
	iface, err := parseSimpleInterfaceResponse(msg)
	if err != nil {
		return err
	}
	q.interfaceIPID = iface.ipid
	debugf("query start ok interface_ipid=%s", q.interfaceIPID)
	if !q.skipOptimize {
		if err := q.optimize(ctx); err != nil && !errors.Is(err, ErrServerNotOptimized) {
			debugf("query optimize failed err=%v", err)
			return err
		}
	}
	return nil
}

// optimize attempts to upgrade the query to use smart enumeration.
func (q *QContext) optimize(ctx context.Context) error {
	debugf("query optimize start ipid=%s", q.interfaceIPID)
	ipid, err := uuidToBin(q.interfaceIPID)
	if err != nil {
		return err
	}

	pdu := bytes.NewBuffer(nil)
	pdu.Write(orpcthis(0))
	pdu.Write(ipid)
	_ = binary.Write(pdu, binary.LittleEndian, uint32(1))
	_ = binary.Write(pdu, binary.LittleEndian, uint16(1))
	pdu.Write([]byte{0xce, 0xce})
	_ = binary.Write(pdu, binary.LittleEndian, uint32(1))
	pdu.Write(iidIWbemFetchSmartEnumBin)

	req := newRPCRequest(3, q.service.proto.remUnknownIPID)
	req.setAppData(pdu.Bytes())
	wire, err := req.signData(q.service.proto)
	if err != nil {
		return err
	}
	reply, err := q.service.proto.roundTrip(ctx, wire)
	if err != nil {
		return err
	}
	msg, err := q.service.proto.responseMessage(reply.fragments)
	if err != nil {
		return err
	}
	opt, err := parseRemQueryInterfaceResponse(msg)
	if err != nil {
		return err
	}

	pdu.Reset()
	pdu.Write(orpcthis(0))
	pdu.Write(ipid)
	req = newRPCRequest(3, opt.ipid)
	req.setAppData(pdu.Bytes())
	wire, err = req.signData(q.service.proto)
	if err != nil {
		return err
	}
	reply, err = q.service.proto.roundTrip(ctx, wire)
	if err != nil {
		return err
	}
	msg, err = q.service.proto.responseMessage(reply.fragments)
	if err != nil {
		return err
	}
	se, err := parseGetSmartEnumResponse(msg)
	if err != nil {
		return err
	}
	_ = q.service.proto.remRelease(ctx, opt.ipid)
	q.interfaceIPID = se.ipid
	q.proxyGUID = se.proxyGUID
	q.smart = true
	debugf("query optimize ok enum_ipid=%s proxy_guid=%s", q.interfaceIPID, previewHex(q.proxyGUID, 8))
	return nil
}

// next retrieves the next result row from the query.
func (q *QContext) next(ctx context.Context, timeout ...uint32) (map[string]*Property, error) {
	if q.interfaceIPID == "" {
		if err := q.start(ctx); err != nil {
			return nil, err
		}
	}
	requestTimeout := q.timeout
	if len(timeout) > 0 {
		requestTimeout = timeout[0]
	}
	var next func(context.Context, uint32) (*objectBlock, error)
	mode := "slow"
	if q.smart {
		debugf("query next smart timeout_ms=%d ipid=%s", requestTimeout, q.interfaceIPID)
		next = q.nextSmart
		mode = "smart"
	} else {
		debugf("query next slow timeout_ms=%d ipid=%s", requestTimeout, q.interfaceIPID)
		next = q.nextSlow
	}
	obj, err := q.nextObject(ctx, requestTimeout, mode, next)
	if err != nil {
		return nil, err
	}
	return obj.properties(
		q.resultOptions.IgnoreDefaults,
		q.resultOptions.IgnoreMissing,
		q.resultOptions.LoadQualifiers,
	)
}

func (q *QContext) nextObject(
	ctx context.Context,
	timeout uint32,
	mode string,
	next func(context.Context, uint32) (*objectBlock, error),
) (*objectBlock, error) {
	for {
		obj, err := next(ctx, timeout)
		if err == nil {
			return obj, nil
		}
		if !errors.Is(err, &Error{Code: wbemSTimedOut}) || timeout == WBEMNoWait {
			return nil, err
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		debugf("query next %s timed out timeout_ms=%d ipid=%s; retrying", mode, timeout, q.interfaceIPID)
	}
}

func (q *QContext) nextSmart(ctx context.Context, timeout uint32) (*objectBlock, error) {
	pdu := bytes.NewBuffer(nil)
	pdu.Write(orpcthis(0))
	pdu.Write(q.proxyGUID)
	_ = binary.Write(pdu, binary.LittleEndian, timeout)
	_ = binary.Write(pdu, binary.LittleEndian, uint32(1))

	req := newRPCRequest(3, q.interfaceIPID)
	req.setAppData(pdu.Bytes())
	wire, err := req.signData(q.service.proto)
	if err != nil {
		return nil, err
	}
	reply, err := q.service.proto.roundTrip(ctx, wire)
	if err != nil {
		return nil, err
	}
	msg, err := q.service.proto.responseMessage(reply.fragments)
	if err != nil {
		return nil, err
	}
	return parseSmartResponse(msg, q.classParts)
}

func (q *QContext) nextSlow(ctx context.Context, timeout uint32) (*objectBlock, error) {
	pdu := bytes.NewBuffer(nil)
	pdu.Write(orpcthis(0))
	_ = binary.Write(pdu, binary.LittleEndian, timeout)
	_ = binary.Write(pdu, binary.LittleEndian, uint32(1))

	req := newRPCRequest(4, q.interfaceIPID)
	req.setAppData(pdu.Bytes())
	wire, err := req.signData(q.service.proto)
	if err != nil {
		return nil, err
	}
	reply, err := q.service.proto.roundTrip(ctx, wire)
	if err != nil {
		return nil, err
	}
	msg, err := q.service.proto.responseMessage(reply.fragments)
	if err != nil {
		return nil, err
	}
	return parseNextBigResponse(msg)
}

// close releases the query resources on the remote server.
func (q *QContext) close(ctx context.Context) error {
	if q.interfaceIPID == "" {
		return nil
	}
	debugf("query close ipid=%s", q.interfaceIPID)
	err := q.service.proto.remRelease(ctx, q.interfaceIPID)
	q.interfaceIPID = ""
	q.classParts = map[string]*classPart{}
	return err
}

// Collect executes the query and returns all result rows in a slice.
func (q *QContext) Collect(ctx context.Context) ([]map[string]*Property, error) {
	var rows []map[string]*Property
	err := q.run(ctx, func(q *QContext) error {
		return q.results(ctx, func(props map[string]*Property) error {
			rows = append(rows, props)
			return nil
		})
	})
	return rows, err
}

// Each returns an iterator over the query result rows. The query is started
// lazily on the first call to the iterator and closed when iteration ends.
//
//	for props, err := range qc.Each(ctx) {
//	    if err != nil { break }
//	    fmt.Println(props["Name"].Value)
//	}
func (q *QContext) Each(ctx context.Context) iter.Seq2[map[string]*Property, error] {
	return func(yield func(map[string]*Property, error) bool) {
		if err := q.start(ctx); err != nil {
			yield(nil, err)
			return
		}
		callerStopped := false
		defer func() {
			closeErr := q.close(ctx)
			if closeErr != nil && !callerStopped {
				yield(nil, closeErr)
			}
		}()
		for {
			props, err := q.next(ctx)
			if err != nil {
				if errors.Is(err, &Error{Code: wbemSFalse}) {
					return
				}
				if !yield(nil, err) {
					callerStopped = true
				}
				return
			}
			if !yield(props, nil) {
				callerStopped = true
				return
			}
		}
	}
}
