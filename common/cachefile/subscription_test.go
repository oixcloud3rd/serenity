package cachefile

import (
	"bytes"
	"context"
	"encoding/binary"
	"testing"
	"time"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/varbin"
)

func TestSubscriptionCacheV2RoundTrip(t *testing.T) {
	ctx := include.Context(context.Background())
	original := Subscription{
		Content:     []option.Outbound{{Type: C.TypeDirect, Tag: "direct", Options: &option.DirectOutboundOptions{}}},
		Endpoints:   []option.Endpoint{{Type: C.TypeTailscale, Tag: "tailnet", Options: &option.TailscaleEndpointOptions{Hostname: "serenity"}}},
		LastUpdated: time.Unix(1784900000, 0),
		LastEtag:    "etag-value",
	}
	content, err := original.MarshalBinary(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if content[0] != 2 {
		t.Fatalf("unexpected cache version: %d", content[0])
	}
	var decoded Subscription
	if err = decoded.UnmarshalBinary(ctx, content); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Content) != 1 || decoded.Content[0].Tag != "direct" {
		t.Fatalf("unexpected outbounds: %#v", decoded.Content)
	}
	if len(decoded.Endpoints) != 1 || decoded.Endpoints[0].Tag != "tailnet" || decoded.Endpoints[0].Type != C.TypeTailscale {
		t.Fatalf("unexpected endpoints: %#v", decoded.Endpoints)
	}
	if !decoded.LastUpdated.Equal(original.LastUpdated) || decoded.LastEtag != original.LastEtag {
		t.Fatalf("metadata mismatch: %#v", decoded)
	}
}

func TestSubscriptionCacheReadsV1OutboundOnly(t *testing.T) {
	ctx := include.Context(context.Background())
	outbounds := []option.Outbound{{Type: C.TypeDirect, Tag: "legacy", Options: &option.DirectOutboundOptions{}}}
	content, err := marshalLegacySubscription(ctx, outbounds, time.Unix(1784900000, 0), "legacy-etag")
	if err != nil {
		t.Fatal(err)
	}
	var decoded Subscription
	if err = decoded.UnmarshalBinary(ctx, content); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Content) != 1 || decoded.Content[0].Tag != "legacy" || len(decoded.Endpoints) != 0 {
		t.Fatalf("unexpected legacy cache result: %#v", decoded)
	}
}

func marshalLegacySubscription(ctx context.Context, outbounds []option.Outbound, updated time.Time, etag string) ([]byte, error) {
	var buffer bytes.Buffer
	buffer.WriteByte(1)
	content, err := json.MarshalContext(ctx, outbounds)
	if err != nil {
		return nil, err
	}
	if _, err = varbin.WriteUvarint(&buffer, uint64(len(content))); err != nil {
		return nil, err
	}
	if _, err = buffer.Write(content); err != nil {
		return nil, err
	}
	if err = binary.Write(&buffer, binary.BigEndian, updated.Unix()); err != nil {
		return nil, err
	}
	if _, err = varbin.WriteUvarint(&buffer, uint64(len(etag))); err != nil {
		return nil, err
	}
	_, err = buffer.WriteString(etag)
	return buffer.Bytes(), err
}
