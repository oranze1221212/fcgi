// client.go в вашем форке fcgi
package fcgi

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
)

// FCGI константы
const (
	FCGI_VERSION_1         = 1
	FCGI_BEGIN_REQUEST     = 1
	FCGI_ABORT_REQUEST     = 2
	FCGI_END_REQUEST       = 3
	FCGI_PARAMS            = 4
	FCGI_STDIN             = 5
	FCGI_STDOUT            = 6
	FCGI_STDERR            = 7
	FCGI_DATA              = 8
	FCGI_GET_VALUES        = 9
	FCGI_GET_VALUES_RESULT = 10
	FCGI_UNKNOWN_TYPE      = 11
	FCGI_MAX_CONNS         = "FCGI_MAX_CONNS"
	FCGI_MAX_REQS          = "FCGI_MAX_REQS"
	FCGI_MPXS_CONNS        = "FCGI_MPXS_CONNS"
)

// FCGIHeader структура заголовка FastCGI
type FCGIHeader struct {
	Version       uint8
	Type          uint8
	RequestID     uint16
	ContentLength uint16
	PaddingLength uint8
	Reserved      uint8
}

// FCGIBeginRequestBody структура тела запроса FCGI_BEGIN_REQUEST
type FCGIBeginRequestBody struct {
	Role     uint16
	Flags    uint8
	Reserved [5]byte
}

// Client структура клиента FastCGI
type Client struct {
	conn      net.Conn
	reader    *bufio.Reader
	requestID uint16
	mu        sync.Mutex
	closed    bool
	closeOnce sync.Once
}

// NewClient создаёт новый клиент FastCGI
func NewClient(network, address string) (*Client, error) {
	conn, err := net.Dial(network, address)
	if err != nil {
		return nil, err
	}
	return &Client{
		conn:      conn,
		reader:    bufio.NewReader(conn),
		requestID: 1, // Начальный идентификатор запроса
	}, nil
}

// Close закрывает соединение
func (c *Client) Close() error {
	var err error
	c.closeOnce.Do(func() {
		err = c.conn.Close()
		c.mu.Lock()
		c.closed = true
		c.mu.Unlock()
	})
	return err
}

// Do отправляет HTTP-запрос через FastCGI и возвращает HTTP-ответ
func (c *Client) Do(req *http.Request) (*http.Response, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil, fmt.Errorf("connection is closed")
	}

	requestID := c.requestID
	c.requestID++ // Увеличиваем ID для следующего запроса

	// Начало запроса
	beginBody := FCGIBeginRequestBody{
		Role:     1, // FCGI_RESPONDER
		Flags:    0, // Не требовать keep-alive
		Reserved: [5]byte{},
	}

	// Создание FCGIHeader для BEGIN_REQUEST
	header := FCGIHeader{
		Version:       FCGI_VERSION_1,
		Type:          FCGI_BEGIN_REQUEST,
		RequestID:     requestID,
		ContentLength: uint16(binary.Size(beginBody)),
		PaddingLength: 0,
		Reserved:      0,
	}

	// Отправка BEGIN_REQUEST
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.BigEndian, beginBody.Role); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.BigEndian, beginBody.Flags); err != nil {
		return nil, err
	}
	if _, err := buf.Write(beginBody.Reserved[:]); err != nil {
		return nil, err
	}

	if err := c.sendRecord(header, buf.Bytes()); err != nil {
		return nil, err
	}

	// Отправка PARAMS
	params := make(map[string]string)

	// Обязательные параметры
	params["SCRIPT_FILENAME"] = req.URL.Path
	params["SCRIPT_NAME"] = req.URL.Path
	params["REQUEST_METHOD"] = req.Method
	params["QUERY_STRING"] = req.URL.RawQuery
	params["CONTENT_TYPE"] = req.Header.Get("Content-Type")
	params["CONTENT_LENGTH"] = fmt.Sprintf("%d", req.ContentLength)
	params["GATEWAY_INTERFACE"] = "CGI/1.1"
	params["SERVER_SOFTWARE"] = "Go-FastCGI-Client/1.0"
	params["REMOTE_ADDR"] = "127.0.0.1" // Замените на реальный IP клиента
	params["SERVER_ADDR"] = "127.0.0.1" // Замените на IP вашего сервера
	params["SERVER_PORT"] = "9000"      // Порт PHP-FPM

	// Копирование заголовков
	for k, v := range req.Header {
		headerName := "HTTP_" + strings.ToUpper(strings.ReplaceAll(k, "-", "_"))
		params[headerName] = strings.Join(v, ",")
	}

	// Преобразование параметров в формат FastCGI
	paramBytes, err := encodeParams(params)
	if err != nil {
		return nil, err
	}

	// Создание FCGIHeader для PARAMS
	paramsHeader := FCGIHeader{
		Version:       FCGI_VERSION_1,
		Type:          FCGI_PARAMS,
		RequestID:     requestID,
		ContentLength: uint16(len(paramBytes)),
		PaddingLength: 0,
		Reserved:      0,
	}

	// Отправка PARAMS
	if err := c.sendRecord(paramsHeader, paramBytes); err != nil {
		return nil, err
	}

	// Завершение PARAMS пустой записью
	emptyParamsHeader := FCGIHeader{
		Version:       FCGI_VERSION_1,
		Type:          FCGI_PARAMS,
		RequestID:     requestID,
		ContentLength: 0,
		PaddingLength: 0,
		Reserved:      0,
	}
	if err := c.sendRecord(emptyParamsHeader, []byte{}); err != nil {
		return nil, err
	}

	// Отправка STDIN (тело запроса)
	var bodyBytes []byte
	if req.Body != nil {
		bodyBytes, err = io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
	}

	stdinHeader := FCGIHeader{
		Version:       FCGI_VERSION_1,
		Type:          FCGI_STDIN,
		RequestID:     requestID,
		ContentLength: uint16(len(bodyBytes)),
		PaddingLength: 0,
		Reserved:      0,
	}

	if err := c.sendRecord(stdinHeader, bodyBytes); err != nil {
		return nil, err
	}

	// Завершение STDIN пустой записью
	emptyStdinHeader := FCGIHeader{
		Version:       FCGI_VERSION_1,
		Type:          FCGI_STDIN,
		RequestID:     requestID,
		ContentLength: 0,
		PaddingLength: 0,
		Reserved:      0,
	}
	if err := c.sendRecord(emptyStdinHeader, []byte{}); err != nil {
		return nil, err
	}

	// Чтение ответа
	responseHeaders := http.Header{}
	var responseBody bytes.Buffer
	var statusCode int = 200
	var finished bool

	for !finished {
		respHeader, respContent, err := c.readRecord()
		if err != nil {
			return nil, err
		}

		switch respHeader.Type {
		case FCGI_STDOUT:
			if respHeader.ContentLength > 0 {
				// Разделение заголовков и тела
				parts := bytes.SplitN(respContent, []byte("\r\n\r\n"), 2)
				if len(parts) == 2 {
					headersPart := string(parts[0])
					bodyPart := parts[1]

					// Разбор заголовков
					for _, line := range strings.Split(headersPart, "\r\n") {
						if strings.HasPrefix(line, "Status: ") {
							fmt.Sscanf(line, "Status: %d", &statusCode)
							continue
						}
						headerParts := strings.SplitN(line, ": ", 2)
						if len(headerParts) == 2 {
							responseHeaders.Add(headerParts[0], headerParts[1])
						}
					}

					responseBody.Write(bodyPart)
				} else {
					// Если нет разделения заголовков и тела
					responseBody.Write(respContent)
				}
			}
		case FCGI_STDERR:
			// Обработка ошибок PHP
			log.Printf("FCGI STDERR: %s", string(respContent))
		case FCGI_END_REQUEST:
			// Завершение запроса
			finished = true
		default:
			// Игнорировать другие типы записей
		}
	}

	// Создание http.Response
	httpResp := &http.Response{
		StatusCode: statusCode,
		Header:     responseHeaders,
		Body:       io.NopCloser(bytes.NewReader(responseBody.Bytes())),
	}

	return httpResp, nil
}

// sendRecord отправляет FCGI запись
func (c *Client) sendRecord(header FCGIHeader, content []byte) error {
	buf := new(bytes.Buffer)
	// Запись заголовка
	if err := binary.Write(buf, binary.BigEndian, header.Version); err != nil {
		return err
	}
	if err := binary.Write(buf, binary.BigEndian, header.Type); err != nil {
		return err
	}
	if err := binary.Write(buf, binary.BigEndian, header.RequestID); err != nil {
		return err
	}
	if err := binary.Write(buf, binary.BigEndian, header.ContentLength); err != nil {
		return err
	}
	if err := binary.Write(buf, binary.BigEndian, header.PaddingLength); err != nil {
		return err
	}
	if err := binary.Write(buf, binary.BigEndian, header.Reserved); err != nil {
		return err
	}

	// Запись содержимого
	if len(content) != int(header.ContentLength) {
		return fmt.Errorf("content length mismatch")
	}
	buf.Write(content)

	// Добавление паддинга
	if header.PaddingLength > 0 {
		buf.Write(make([]byte, header.PaddingLength))
	}

	// Отправка данных
	_, err := c.conn.Write(buf.Bytes())
	return err
}

// readRecord читает FCGI запись
func (c *Client) readRecord() (FCGIHeader, []byte, error) {
	var header FCGIHeader
	if err := binary.Read(c.reader, binary.BigEndian, &header.Version); err != nil {
		return header, nil, err
	}
	if err := binary.Read(c.reader, binary.BigEndian, &header.Type); err != nil {
		return header, nil, err
	}
	if err := binary.Read(c.reader, binary.BigEndian, &header.RequestID); err != nil {
		return header, nil, err
	}
	if err := binary.Read(c.reader, binary.BigEndian, &header.ContentLength); err != nil {
		return header, nil, err
	}
	if err := binary.Read(c.reader, binary.BigEndian, &header.PaddingLength); err != nil {
		return header, nil, err
	}
	if err := binary.Read(c.reader, binary.BigEndian, &header.Reserved); err != nil {
		return header, nil, err
	}

	content := make([]byte, header.ContentLength)
	if _, err := io.ReadFull(c.reader, content); err != nil {
		return header, nil, err
	}

	// Пропуск паддинга
	if header.PaddingLength > 0 {
		if _, err := c.reader.Discard(int(header.PaddingLength)); err != nil {
			return header, nil, err
		}
	}

	return header, content, nil
}

// encodeParams кодирует параметры в формат FastCGI
func encodeParams(params map[string]string) ([]byte, error) {
	buf := new(bytes.Buffer)
	for k, v := range params {
		keyLen := len(k)
		valueLen := len(v)

		// Определение длины ключа
		if keyLen < 128 {
			buf.WriteByte(byte(keyLen))
		} else {
			buf.WriteByte(byte((keyLen>>24)&0x7F | 0x80))
			buf.WriteByte(byte((keyLen >> 16) & 0xFF))
			buf.WriteByte(byte((keyLen >> 8) & 0xFF))
			buf.WriteByte(byte(keyLen & 0xFF))
		}

		// Определение длины значения
		if valueLen < 128 {
			buf.WriteByte(byte(valueLen))
		} else {
			buf.WriteByte(byte((valueLen>>24)&0x7F | 0x80))
			buf.WriteByte(byte((valueLen >> 16) & 0xFF))
			buf.WriteByte(byte((valueLen >> 8) & 0xFF))
			buf.WriteByte(byte(valueLen & 0xFF))
		}

		// Запись ключа и значения
		buf.WriteString(k)
		buf.WriteString(v)
	}
	return buf.Bytes(), nil
}
