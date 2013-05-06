
import xml.etree.ElementTree as ET
from gateway import Gateway
from ConfigParser import ConfigParser,ParsingError


"""
>> parse xml file to dict
>> the dict looks like:
{'switch': [{'border': 'false', 'port': [{'prefixlen': '24', 'ip': '192.168.1.1', 'mac': 'hello_mac', 'num': '0', 'name': 'eth0'}, {'prefixlen': '24', 'ip': '192.168.2.1', 'mac': 'world_mac', 'num': '1', 'name': 'eth1'}], 'name': 's1'}, {'border': 'true', 'port': [{'prefixlen': '24', 'ip': '192.168.3.1', 'mac': 'hello_mac', 'num': '0', 'name': 'eth0'}, {'prefixlen': '24', 'ip': '192.168.4.1', 'mac': 'world_mac', 'num': '1', 'name': 'eth1'}], 'name': 's2'}]}

>> convert dict to dict switches{}
switches[name] = {port_no:Gateway,,,}

TODO:the border is not used
"""

class XmlListConfig(list):
    def __init__(self, aList):
        for element in aList:
            if len(element) != 0:
                # treat like dict
                if len(element) == 1 or element[0].tag != element[1].tag:
                    self.append(XmlDictConfig(element))
                # treat like list
                elif element[0].tag == element[1].tag:
                    self.append(XmlListConfig(element))
            elif element.text:
                text = element.text.strip()
                if text:
                    self.append(text)

class XmlDictConfig(dict):
    def __init__(self, parent_element):
        childrenNames = []
        for child in parent_element.getchildren():
            childrenNames.append(child.tag)

        if parent_element.items():
            self.update(dict(parent_element.items()))
        for element in parent_element:
            if len(element) != 0:
                # treat like dict - we assume that if the first two tags
                # in a series are different, then they are all different.
                if len(element) == 1 or element[0].tag != element[1].tag:
                    aDict = XmlDictConfig(element)
                # treat like list - we assume that if the first two tags
                # in a series are the same, then the rest are the same.
                else:
                    # here, we put the list in dictionary; the key is the
                    # tag name the list elements all share in common, and
                    # the value is the list itself 
                    aDict = {element[0].tag: XmlListConfig(element)}
                # if the tag has attributes, add those to the dict
                if element.items():
                    aDict.update(dict(element.items()))
                if childrenNames.count(element.tag) > 1:
                    try:
                        currentValue = self[element.tag]
                        currentValue.append(aDict)
                        self.update({element.tag: currentValue})
                    except: #the first of its kind, an empty list must be created
                        self.update({element.tag: [aDict]}) #aDict is written in [], i.e. it will be a list
                else:
                    self.update({element.tag: aDict})
            # this assumes that if you've got an attribute in a tag,
            # you won't be having any text. This may or may not be a 
            # good idea -- time will tell. It works for the way we are
            # currently doing XML configuration files...
            elif element.items():
                self.update({element.tag: dict(element.items())})
            # finally, if there are no child tags and no attributes, extract
            # the text
            else:
                self.update({element.tag: element.text})

def read_cfg(filepath):

    tree = None
    switches = {}
    try:
        tree = ET.parse(filepath)
        dic = to_dict(tree)
        switches = to_switches(dic)
    except ET.ParseError as e:
        print 'File %s Parse Error :'% filepath,e
    except Exception as e:
        print 'File %s Parse Error :'% filepath,e
    finally:
        return switches

def to_dict(tree):
    xmldict = {}
    if tree is not None and tree.getroot() is not None:
        xmldict = XmlDictConfig(tree.getroot())
    return xmldict

def to_switches(xmldic):
    dic_switches = {}   # switch[name] = {port_no:gateway,,,}
    switches = xmldic.get('switch')
    if not switches:
        print 'no switch'
    else:
        if isinstance(switches,list):
            for switch in switches:
                name = switch.get('name') if switch.get('name') is not None else 'undefine'
                dic_switches[name] = handle_switch(switch)
        elif isinstance(switches,dict):
            name = switches.get('name') if switches.get('name') is not None else 'undefine'
            dic_switches[name] = handle_switch(switches)
        else:
            print 'switches type:',type(switches)
    return dic_switches

def handle_switch(switch):
    dic_ports = {}
    ports = switch.get('port')
    if not ports:
            print 'no port'
    else:
        if isinstance(ports, list):
            for port in ports:
                num = port.get('num') if port.get('num') is not None else 'undefine'
                dic_ports[int(num)] = handle_port(port)
        elif isinstance(ports, dict):
            num = ports.get('num') if ports.get('num') is not None else 'undefine'
            dic_ports[int(num)] = handle_port(ports)
        else:
            print 'ports type:',type(ports)
    return dic_ports
    
def handle_port(port):
    kwargs = port
    gw = Gateway(**kwargs)
    return gw

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
    filepath = 'config.xml'
    switches_cfg = read_cfg(filepath)
    s1 = switches_cfg.get('s1')
    s2 = switches_cfg.get('s2')
    print s2.get('0')
    if s1:
        port1 = s1.get('1') # s1[port_no] = Gateway
        print port1
    filepath = 'bgper.config'
    d = read_bgp_config(filepath)
    if d:
        print d

