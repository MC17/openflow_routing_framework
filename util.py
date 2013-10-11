from gateway import Gateway
from ConfigParser import ConfigParser,ParsingError


def read_cfg(filepath):
    ans = {}
    f = file(filepath)
    for line in f:
        line = line.split()
        if '#' in line or line == []:
            continue
        switch_name, port_name, port_no, gw_ipv4, ipv4_prefix_len, \
        gw_ipv6, ipv6_prefix_len, border = line
        port_no = int(port_no)
        ipv4_prefix_len = int(ipv4_prefix_len)
        ipv6_prefix_len = int(ipv6_prefix_len)
        border = True if border == 'True' else False
        if switch_name not in ans:
            ans[switch_name] = {}
        ans[switch_name][port_no] = Gateway(port_name, gw_ipv4, gw_ipv6,
                                    port_no, ipv4_prefix_len, ipv6_prefix_len,
                                    border)
    return ans

def read_bgp_config(filepath):
    dict_ = {}
    config = ConfigParser()
    try:
        config.read(filepath)
        section = 'bgper'
        options = config.options(section)
        for option in options:
            dict_[option] = config.get(section, option)
    except IOError as e:
        print "I/O error({0}):{1}".formate(e.errno,e.strerror)
    except ParsingError as e:
        print e
    return dict_

if __name__ == '__main__':
    filepath = 'routing.config'
    switches_cfg = read_cfg(filepath)
    s1 = switches_cfg.get('s1')
    s2 = switches_cfg.get('s2')
    print s1, s2, switches_cfg

    filepath = 'bgper.config'
    d = read_bgp_config(filepath)
    if d:
        print d

