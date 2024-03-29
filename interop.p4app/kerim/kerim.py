from mininet.link import Intf
from p4_mininet import P4RuntimeSwitch
from p4_program import P4Program

from internet_router import InternetRouter


class KerimSwitch(P4RuntimeSwitch):
    def __init__(self, *opts, **kwargs):
        self.controller = None

        prog = kwargs.get('prog')
        if prog is None:
            raise Exception('Must specify p4 program')
        prog = P4Program(prog)

        if prog.version == 14:
            sw_path = 'simple_switch'
            enable_grpc = False
        elif prog.version == 16:
            sw_path = 'simple_switch_grpc'
            enable_grpc = True
        else:
            raise Exception('Switch does not support P4 version %s' % prog.version)

        self.ctrl_args = dict()
        if 'ctrl_args' in kwargs:
            self.ctrl_args = kwargs['ctrl_args']
            del kwargs['ctrl_args']

        kwargs.update({
            'enable_grpc': enable_grpc,
            'cli_path': 'simple_switch_CLI',
            'sw_path': sw_path,
            'program': prog,
            'start_controller': True,
        })

        P4RuntimeSwitch.__init__(self, *opts, **kwargs)

    def initTable(self):
        bcast_mgid = 1
        ctrl_port = self.ctrl_args.get('ctrl_port', 1)
        # Broadcast to ports except for 0 (lo) and ctrl_port
        bcast_ports = [p for p in self.intfs.keys() if p not in [0, ctrl_port]]
        self.addMulticastGroup(mgid=bcast_mgid, ports=bcast_ports)
        self.insertTableEntry(table_name='MyIngress.fwd_l2',
                              match_fields={'hdr.ethernet.dstAddr': ["ff:ff:ff:ff:ff:ff"]},
                              action_name='MyIngress.set_mgid',
                              action_params={'mgid': bcast_mgid})
        #
        # switch.insertTableEntry(table_name='MyIngress.routing_table',
        #                         match_fields={'hdr.ipv4.dstAddr': ['10.0.%d.0' % i, 24]},
        #                         action_name='MyIngress.route',
        #                         action_params={'nextHop': '10.0.%d.2' % i,
        #                                        'port': 2})

        # PWOSFP Hello!
        self.insertTableEntry(table_name='MyIngress.routing_table',
                              match_fields={'hdr.ipv4.dstAddr': ['224.0.0.5', 32]},
                              action_name='MyIngress.route',
                              action_params={'nextHop': '224.0.0.5',
                                             'port': 3})

        self.insertTableEntry(table_name='MyIngress.arp_table',
                              match_fields={'meta.nextHop': '224.0.0.5'},
                              action_name='MyIngress.arp_lookup',
                              action_params={'nextHopMac': '00:00:00:11:22:33'})

    def start(self, controllers):
        super(KerimSwitch, self).start(controllers)
        self.initTable()
        self.controller = InternetRouter(self, **self.ctrl_args)
        self.controller.start()

    def stop(self):
        if self.controller is not None:
            self.controller.join()
        super(KerimSwitch, self).stop()
