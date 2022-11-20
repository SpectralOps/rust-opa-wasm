package test

output_1 := net.cidr_contains_matches({"x": "1.1.0.0/16"}, [["1.1.1.128", "foo"]])

output_2 := net.cidr_contains_matches("1.1.0.0/16", "1.1.1.128")

output_3 := net.cidr_contains_matches(["1.1.0.0/16"], ["1.1.1.128"])

output_4 := net.cidr_contains_matches([["1.1.0.0/16"]], [["1.1.1.128"]])

output_5 := net.cidr_contains_matches([["1.1.0.0/16", "x"]], [["1.1.1.128", "y"], ["2.2.2.2", "z"]])

output_6 := net.cidr_contains_matches([["1.1.0.0/16", "x"]], {"y": ["1.1.1.128", "foo"], "z": ["2.2.2.2", "bar"]})

output_7 := net.cidr_contains_matches([["1.1.0.0/16", "x"]], {"y": "1.1.1.128", "z": "2.2.2.2"})

# from docs

docs_test_1 := net.cidr_contains_matches("1.1.1.0/24", "1.1.1.128")

docs_test_2 := net.cidr_contains_matches(["1.1.1.0/24", "1.1.2.0/24"], "1.1.1.128")

docs_test_3 := net.cidr_contains_matches([["1.1.0.0/16", "foo"], "1.1.2.0/24"], ["1.1.1.128", ["1.1.254.254", "bar"]])

# https://github.com/open-policy-agent/opa/issues/3252
# notice sets are reversing the order on WASM, stated by design
# and a WASM vs Rego thing we'll "have to live with"
# the engine will flip
# ["1.1.0.0/16", "foo"], "1.1.2.0/24"
# to be:
# "1.1.2.0/24", ["1.1.0.0/16", "foo"], 
# and so, index in the result is '1' and not '0' like in the docs
docs_test_4 := net.cidr_contains_matches({"1.1.2.0/24", ["1.1.0.0/16", "foo"]}, {"x": "1.1.1.128", "y": ["1.1.254.254", "bar"]})

# switching to arrays works as intended, which is the recommended workaround
docs_test_4_1 := net.cidr_contains_matches([["1.1.0.0/16", "foo"], "1.1.2.0/24"], {"x": "1.1.1.128", "y": ["1.1.254.254", "bar"]})

cidr_expand_1 := net.cidr_expand("1.1.0.0/30")

cidr_expand_2 := net.cidr_expand("1.1.0.0/32")

cidr_expand_3 := net.cidr_expand("2002::1234:abcd:ffff:c0a8:101/128")

cidr_expand_4 := net.cidr_expand("2002::1234:abcd:ffff:c0a8:101/127")

cidr_merge_1 := net.cidr_merge(["192.0.128.0/24", "192.0.129.0/24"])

cidr_merge_2 := net.cidr_merge(["1900::1/96", "1900::20/64"])

# will example.com forever be: 93.184.216.34 ?
# taking the risk of years in the future this test fails because they
# changed IPs. So this will go out to network to do the lookup:
net_lookup := net.lookup_ip_addr("www.example.com")
