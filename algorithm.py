import time


class Algorithm(object):
    '''
        algorithm base class
    '''
    def __init__(self, dpid_to_switch):
        self.dpid_to_switch = dpid_to_switch
        self.topology_last_update = time.time()

    def find_route(self, src, dst):
        '''
            sub classes should implement this method to calculate
            the route and return a list of switches, indicating the
            path to destination, i.e. [src, ..., dst]
         '''
        return None

    
class Dijkstra(Algorithm):

    class Heap(object):
        '''
            a minimal heap stores tuple (switch, distance)
        '''
        def __init__(self):
            self.heap = []
            self.switch_to_position = {}    # maps switch to index in the heap

        def insert(self, switch, dist):
            self.heap.append((switch, dist))
            self.switch_to_position[switch] = len(self.heap) - 1
            self._shift_to_root(len(self.heap) - 1)

        def _shift_to_root(self, position):
            while position > 0 and \
                    self.heap[position][1] < self.heap[(position-1)/2][1]:
                self._exchange(position, (position-1)/2)
                position = (position-1) / 2

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

        def _shift_to_leaf(self, position):
            length = len(self.heap)
            while position*2+1 < length:
                if position*2+2 < length:
                    if self.heap[position*2+1][1] < self.heap[position*2+2][1]:
                        if self.heap[position][1] > self.heap[position*2+1][1]:
                            self._exchange(position, position*2+1)
                            #print 'exchange', position, position*2+1
                            position = position * 2 + 1
                        else:
                            break
                    else:
                        if self.heap[position][1] > self.heap[position*2+2][1]:
                            self._exchange(position, position*2+2)
                            #print 'exchange', position, position*2+2
                            position = position * 2 + 2
                        else:
                            break
                else:
                    if self.heap[position][1] > self.heap[position*2+1][1]:
                        self._exchange(position, position*2+1)
                        position = position * 2 + 1
                    else:
                        break

        def _exchange(self, x, y):
            # x and y are positions in self.heap
            self.heap[x], self.heap[y] = self.heap[y], self.heap[x]
            self.switch_to_position[self.heap[x][0]] = x
            self.switch_to_position[self.heap[y][0]] = y

        def update(self, switch, distance):
            position = self.switch_to_position[switch]
            self.heap[position] = (switch, distance)
            self._shift_to_leaf(position)
            self._shift_to_root(position)


    def __init__(self, *args, **kwargs):
        super(Dijkstra, self).__init__(*args, **kwargs)
        self.path = {}  # path[(src, dest)] = [list of path from src to dest]
        self.route_last_update = time.time()

    def find_route(self, src, dst):
        if self.route_last_update < self.topology_last_update:
            self.path = {}
            self.route_last_update = time.time()

        try:
            path = self.path[src, dst]
            return path
        except:
            pass

        pq = Dijkstra.Heap()
        distance = {}   # distance[switch] = distance
        previous = {}   # previous[switch] = switch/None
        for dpid, switch in self.dpid_to_switch.iteritems():
            if switch != src:
                distance[switch] = float('inf')
            else:
                distance[switch] = 0

            previous[switch] = None
            pq.insert(switch, distance[switch])
        while True:
            x = pq.pop()
            if x is None:
                break

            switch, dist = x
            if switch == dst:
                path = [dst]
                while previous[switch]:
                    path.insert(0, previous[switch])
                    switch = previous[switch]
                self.path[src, dst] = path
                print 'path calculated:'
                for i in path:
                    print i
                return path

            for port_no, port in switch.ports.iteritems():
                peer_switch = self.dpid_to_switch.get(port.peer_switch_dpid,
                                                      None)
                if peer_switch is None:
                    continue
                if dist + port.cost < distance[peer_switch]:
                    distance[peer_switch] = dist + port.cost
                    pq.update(peer_switch, dist + port.cost)
                    previous[peer_switch] = switch
            
        return None
