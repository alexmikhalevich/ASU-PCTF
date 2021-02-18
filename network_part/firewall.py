import iptc

def add_rule(port_no):
    rule_tcp = iptc.Rule()
    rule_tcp.protocol = "tcp"
    match = iptc.Match(rule_tcp, "tcp")
    match.sport = port_no
    rule_tcp.add_match(match)
    rule_tcp.target = iptc.Target(rule_tcp, "DROP")
    chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
    chain.insert_rule(rule_tcp)

    rule_udp = iptc.Rule()
    rule_udp.protocol = "udp"
    match = iptc.Match(rule_udp, "udp")
    match.sport = port_no
    rule_udp.add_match(match)
    rule_udp.target = iptc.Target(rule_udp, "DROP")
    chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
    chain.insert_rule(rule_udp)

def flush():
    chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
    chain.flush()