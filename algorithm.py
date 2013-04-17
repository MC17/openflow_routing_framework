
class Algorithm(object):
    '''
        algorithm base class
    '''
    def __init__(self, dpid_to_switch):
        self.dpid_to_switch = dpid_to_switch

    def find_route(self, src, dst):
        '''
            sub classes should implement this method to calculate
            the route and return a list of switches, indicating the
            path to destination.
            the list should include the src_switch but exclude the
            dst_switch(`[src, dst)`)
         '''
        return None

    
class Instruction(object):
    '''
        data structure returned by algorithm
    '''

    # XXX


class Dijkstra(Algorithm):

    class Heap(object):
        '''
            a minimal heap stores (switch, distance)
        '''
        def __init__(self):
            self.heap = []
            self.switch_to_position = {}    # maps switch to index in the heap

        def insert(self, switch, dist):
            self.heap.append((switch, dist))
            self.switch_to_position[switch] = len(self.heap) - 1
            self._shift_to_root(len(self.heap) - 1)

        def _shift_to_root(self, positon):
            while positon > 0 and \
                    self.heap[positon][1] < self.heap[(positon-1)/2][1]:
                self._exchange(positon, (positon-1)/2)
                positon = (positon-1) / 2

        def pop(self):
            length = len(self.heap)
            if length == 0:
                return None

            ans = self.heap[0]

            self.heap[0] = self.heap[length - 1]
            self.switch_to_position[self.heap[0][0]] = 0
            self.heap.pop()
            del self.switch_to_position[ans[0]]

            self._shift_to_leaf(0)
                        
            return ans

        def _shift_to_leaf(self, positon):
            length = len(self.heap)
            while positon*2+1 < length:
                if positon*2+2 < length:
                    if self.heap[positon*2+1][1] < self.heap[positon*2+2][1]:
                        if self.heap[positon][1] > self.heap[positon*2+1][1]:
                            self._exchange(positon, positon*2+1)
                            #print 'exchange', positon, positon*2+1
                            positon = positon * 2 + 1
                        else:
                            break
                    else:
                        if self.heap[positon][1] > self.heap[positon*2+2][1]:
                            self._exchange(positon, positon*2+2)
                            #print 'exchange', positon, positon*2+2
                            positon = positon * 2 + 2
                        else:
                            break
                else:
                    if self.heap[positon][1] > self.heap[positon*2+1][1]:
                        self._exchange(positon, positon*2+1)
                        positon = positon * 2 + 1
                    else:
                        break

        def _exchange(self, x, y):
            # x and y are positons in self.heap
            self.heap[x], self.heap[y] = self.heap[y], self.heap[x]
            self.switch_to_position[self.heap[x][0]] = x
            self.switch_to_position[self.heap[y][0]] = y

        def update(self, switch, distance):
            positon = self.switch_to_position[switch]
            self.heap[positon] = (switch, distance)
            self._shift_to_leaf(positon)
            self._shift_to_root(positon)



    def __init__(self, *args, **kwargs):
        super(Dijkstra, self).__init__(*args, **kwargs)
        self.path = {}  # path[(src, dest)] = [list of path from src to dest]
        self.need_recalculate = False

    def find_route(self, src, dst):
        if self.need_recalculate:
            self.path = {}
            self.need_recalculate = False

        try:
            path = self.path[src, dst]
            return path
        except:
            pass

        pq = Heap()
        distance = {}   # distance[switch] = distance
        previous = {}   # previous[switch] = switch/None
        for dpid, switch in self.dpid_to_switch.interitems():
            if switch != src:
                distance[switch] = float('inf')
            else:
                distance[switch] = 0

            previous[switch] = None
            pq.insert(switch, distance[switch])
        while True:
            x = pq.pop()
            if x == None:
                break

            switch, dist = x
            if switch == dst:
                path = []
                while previous[switch]:
                    path.insert(0, previous[switch])
                    switch = previous[switch]
                self.path[src, dst] = path
                return path

            for port_no, port in switch.ports.iteritems():
                peer_switch = self.dpid_to_switch[port.peer_switch_dpid]
                if peer_switch == None:
                    continue
                if dist + port.cost < distance[peer_switch]:
                    distance[peer_switch] = dist + port.cost
                    pq.update(peer_switch, dist + port.cost)
                    previous[peer_switch] = switch
            
        return None
