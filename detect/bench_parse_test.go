package detect

import "testing"

func BenchmarkParseCombined(b *testing.B) {
	p, _ := NginxParser(`$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"`, "")
	line := []byte(`203.0.113.7 - - [15/Nov/2026:10:11:12 +0800] "GET /wp-admin/admin-ajax.php?action=x&id=1 HTTP/1.1" 200 512 "https://shop.test/a" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"`)
	for i := 0; i < b.N; i++ {
		p.Parse(line)
	}
}
