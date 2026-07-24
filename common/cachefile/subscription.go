package cachefile

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"time"

	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/varbin"
)

type Subscription struct {
	Content     []option.Outbound
	Endpoints   []option.Endpoint
	LastUpdated time.Time
	LastEtag    string
}

func (c *Subscription) MarshalBinary(ctx context.Context) ([]byte, error) {
	var buffer bytes.Buffer
	buffer.WriteByte(2)
	content, err := json.MarshalContext(ctx, c.Content)
	if err != nil {
		return nil, err
	}
	_, err = varbin.WriteUvarint(&buffer, uint64(len(content)))
	if err != nil {
		return nil, err
	}
	_, err = buffer.Write(content)
	if err != nil {
		return nil, err
	}
	endpoints, err := json.MarshalContext(ctx, c.Endpoints)
	if err != nil {
		return nil, err
	}
	_, err = varbin.WriteUvarint(&buffer, uint64(len(endpoints)))
	if err != nil {
		return nil, err
	}
	_, err = buffer.Write(endpoints)
	if err != nil {
		return nil, err
	}
	err = binary.Write(&buffer, binary.BigEndian, c.LastUpdated.Unix())
	if err != nil {
		return nil, err
	}
	_, err = varbin.WriteUvarint(&buffer, uint64(len(c.LastEtag)))
	if err != nil {
		return nil, err
	}
	_, err = buffer.WriteString(c.LastEtag)
	if err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func (c *Subscription) UnmarshalBinary(ctx context.Context, data []byte) error {
	reader := bytes.NewReader(data)
	version, err := reader.ReadByte()
	if err != nil {
		return err
	}
	if version != 1 && version != 2 {
		return E.New("unsupported subscription cache version: ", version)
	}
	contentLength, err := binary.ReadUvarint(reader)
	if err != nil {
		return err
	}
	content := make([]byte, contentLength)
	_, err = io.ReadFull(reader, content)
	if err != nil {
		return err
	}
	err = json.UnmarshalContext(ctx, content, &c.Content)
	if err != nil {
		return err
	}
	if version >= 2 {
		endpointsLength, err := binary.ReadUvarint(reader)
		if err != nil {
			return err
		}
		endpoints := make([]byte, endpointsLength)
		_, err = io.ReadFull(reader, endpoints)
		if err != nil {
			return err
		}
		err = json.UnmarshalContext(ctx, endpoints, &c.Endpoints)
		if err != nil {
			return err
		}
	}
	var lastUpdatedUnix int64
	err = binary.Read(reader, binary.BigEndian, &lastUpdatedUnix)
	if err != nil {
		return err
	}
	c.LastUpdated = time.Unix(lastUpdatedUnix, 0)
	etagLength, err := binary.ReadUvarint(reader)
	if err != nil {
		return err
	}
	etag := make([]byte, etagLength)
	_, err = io.ReadFull(reader, etag)
	if err != nil {
		return err
	}
	c.LastEtag = string(etag)
	return nil
}
