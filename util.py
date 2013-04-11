
import xml.etree.ElementTree as ET


"""
parse xml file to dict
the dict looks like:
{'switches': {'switch': {'border': 'false', 'port': [{'prefixlen': '24', 'ip': '192.168.1.1', 'mac': 'hello_mac', 'name': '0'}, {'prefixlen': '24', 'ip': '192.168.2.1', 'mac': 'world_mac', 'name': '1'}], 'name': 's1'}}}

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
    dic = {}
    try:
        tree = ET.parse(filepath)
	dic = to_dict(tree)
    except ET.ParseError as e:
	print e
    finally:
        return dic

def to_dict(tree):
    xmldict = {}
    if tree is not None and tree.getroot() is not None:
        xmldict = XmlDictConfig(tree.getroot())
    return xmldict
	
    
if __name__ == '__main__':
    filepath = 'config.xml'
    dic = read_cfg(filepath)
    print dic

















