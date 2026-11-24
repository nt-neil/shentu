package engine

import (
	"maps"
	"slices"
	"strings"
	"testing"
)

// phpNameKinds is what every PHP rule pattern name (a name followed by "(")
// that PHP also has as a function is taken for: "function", a call of PHP's
// function, which new X( and A\X( are not; or "class", written for
// new X(...). phpFuncPattern decides by the case the rule writes the name in:
// lower case is a function. Key is php-jwt's Firebase\JWT\Key (PHP's key()
// reads an array).
var phpNameKinds = map[string]string{
	"Key":                                  "class",
	"array_filter":                         "function",
	"array_map":                            "function",
	"array_walk":                           "function",
	"assert":                               "function",
	"basename":                             "function",
	"call_user_func":                       "function",
	"call_user_func_array":                 "function",
	"copy":                                 "function",
	"count":                                "function",
	"crypt":                                "function",
	"curl_init":                            "function",
	"curl_setopt":                          "function",
	"exec":                                 "function",
	"exif_imagetype":                       "function",
	"exif_read_data":                       "function",
	"file":                                 "function",
	"file_exists":                          "function",
	"file_get_contents":                    "function",
	"file_put_contents":                    "function",
	"filesize":                             "function",
	"filter_input":                         "function",
	"fopen":                                "function",
	"forward_static_call":                  "function",
	"forward_static_call_array":            "function",
	"fpassthru":                            "function",
	"fsockopen":                            "function",
	"ftp_login":                            "function",
	"get_headers":                          "function",
	"getimagesize":                         "function",
	"hash":                                 "function",
	"hash_file":                            "function",
	"hash_hmac":                            "function",
	"highlight_file":                       "function",
	"imagecreatefromgif":                   "function",
	"imagecreatefromjpeg":                  "function",
	"imagecreatefrompng":                   "function",
	"imagecreatefromwebp":                  "function",
	"is_file":                              "function",
	"iterator_apply":                       "function",
	"json_decode":                          "function",
	"ldap_bind":                            "function",
	"ldap_list":                            "function",
	"ldap_read":                            "function",
	"ldap_search":                          "function",
	"libxml_disable_entity_loader":         "function",
	"mail":                                 "function",
	"md5":                                  "function",
	"md5_file":                             "function",
	"move_uploaded_file":                   "function",
	"mysqli_connect":                       "function",
	"mysqli_multi_query":                   "function",
	"mysqli_prepare":                       "function",
	"mysqli_real_connect":                  "function",
	"mysqli_real_query":                    "function",
	"openssl_decrypt":                      "function",
	"openssl_encrypt":                      "function",
	"passthru":                             "function",
	"pfsockopen":                           "function",
	"popen":                                "function",
	"preg_replace_callback":                "function",
	"printf":                               "function",
	"proc_open":                            "function",
	"readfile":                             "function",
	"realpath":                             "function",
	"rename":                               "function",
	"rmdir":                                "function",
	"sha1":                                 "function",
	"sha1_file":                            "function",
	"shell_exec":                           "function",
	"simplexml_load_file":                  "function",
	"simplexml_load_string":                "function",
	"sizeof":                               "function",
	"socket_connect":                       "function",
	"sodium_crypto_aead_aes256gcm_decrypt": "function",
	"sodium_crypto_aead_aes256gcm_encrypt": "function",
	"sodium_crypto_aead_chacha20poly1305_ietf_decrypt":  "function",
	"sodium_crypto_aead_chacha20poly1305_ietf_encrypt":  "function",
	"sodium_crypto_aead_xchacha20poly1305_ietf_decrypt": "function",
	"sodium_crypto_aead_xchacha20poly1305_ietf_encrypt": "function",
	"sodium_crypto_secretbox":                           "function",
	"sodium_crypto_secretbox_open":                      "function",
	"str_starts_with":                                   "function",
	"stream_socket_client":                              "function",
	"strncmp":                                           "function",
	"strpos":                                            "function",
	"system":                                            "function",
	"uasort":                                            "function",
	"uksort":                                            "function",
	"unlink":                                            "function",
	"unserialize":                                       "function",
	"usort":                                             "function",
	"vprintf":                                           "function",
}

// TestPHPNameKinds: a rule pattern name that collides with a PHP function is
// decided on purpose, as a function or as a class, and listed in
// phpNameKinds, so a new rule naming one fails here until it is.
func TestPHPNameKinds(t *testing.T) {
	e := engineForTest(t)
	got := map[string]string{}
	for _, c := range e.byLang["php"] {
		for _, list := range [][]*pat{c.sources, c.sinks, c.sanitizers} {
			for _, p := range list {
				if len(p.toks) < 2 || p.toks[0].Kind != Ident || !p.toks[1].op("(") {
					continue
				}
				name := p.toks[0].Text
				if !phpBuiltins[strings.ToLower(name)] {
					continue
				}
				kind := "class"
				if phpFuncPattern(name) {
					kind = "function"
				}
				got[name] = kind
			}
		}
	}
	if !maps.Equal(got, phpNameKinds) {
		var diff []string
		for _, n := range slices.Sorted(maps.Keys(got)) {
			if phpNameKinds[n] != got[n] {
				listed := phpNameKinds[n]
				if listed == "" {
					listed = "not listed"
				}
				diff = append(diff, n+": read as "+got[n]+", listed: "+listed)
			}
		}
		for _, n := range slices.Sorted(maps.Keys(phpNameKinds)) {
			if got[n] == "" {
				diff = append(diff, n+": listed, but no PHP rule names it any more")
			}
		}
		t.Errorf("PHP rule pattern names that PHP also has as functions differ from phpNameKinds:\n  %s\n"+
			"A name written in lower case is read as PHP's function, so new X( and A\\X( do not match it; "+
			"any other spelling is read as a class. Decide which the rule means: for the function, write the name "+
			"in lower case in the rule; for a class, write it as the class is spelt. Then add the name to "+
			"phpNameKinds in phpnames_test.go with that reading (a class with the class it is), or drop a name "+
			"no rule names any more.", strings.Join(diff, "\n  "))
	}
}
