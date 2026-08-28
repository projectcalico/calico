#!/usr/bin/env python3

from pydot import Dot
from pydot import Edge
from pydot import Node


def main():
    graph = Dot('Controller Dependency Graph')

    # controller node list
    graph.add_node(Node('apiserver', label='APIServer', shape='box'))
    graph.add_node(Node('applicationlayer', label='ApplicationLayer', shape='box'))
    graph.add_node(Node('authentication', label='Authentication', shape='box'))
    graph.add_node(Node('clusterconnection',
                   label='{ClusterConnection|Standalone\nManagementCluster\nManagementClusterConnection}', shape='record'))
    graph.add_node(Node('compliance', label='Compliance', shape='box'))
    graph.add_node(Node('installation', label='Installation', shape='box'))
    graph.add_node(Node('intrusiondetection',
                   label='IntrusionDetection', shape='box'))
    graph.add_node(Node('logcollector', label='LogCollector', shape='box'))
    graph.add_node(Node('logstorage', label='LogStorage', shape='box'))
    graph.add_node(Node('manager', label='Manager', shape='box'))
    graph.add_node(Node('monitor', label='Monitor', shape='box'))

    # The controller dependencies are deduced from controller Reconcile() function.
    # This is still a manual process at the moment.
    # [APIServer] --> [ClusterConnection]
    # [APIServer] -> [Installation]
    graph.add_edge(Edge('apiserver', 'clusterconnection', label='Enterprise', style='dashed'))
    graph.add_edge(Edge('apiserver', 'installation'))
    # [ApplicationLayer] -> [Installation]
    graph.add_edge(Edge('applicationlayer', 'installation'))
    # [Authentication] -> [ClusterConnection]
    # [Authentication] -> [Installation]
    graph.add_edge(Edge('authentication', 'clusterconnection', style='dashed'))
    graph.add_edge(Edge('authentication', 'installation'))
    # [ClusterConnection|ManagementCluster;ManagementClusterConnection] -> [Installation]
    graph.add_edge(Edge('clusterconnection', 'installation', style='dashed'))
    # [Compliance] -> [Authentication]
    # [Compliance] -> [ClusterConnection]
    # [Compliance] -> [Installation]
    # [Compliance] -> [LogStorage]
    graph.add_edge(Edge('compliance', 'authentication'))
    graph.add_edge(Edge('compliance', 'clusterconnection', style='dashed'))
    graph.add_edge(Edge('compliance', 'installation'))
    graph.add_edge(Edge('compliance', 'logstorage'))
    # [IntrusionDetection] -> [ClusterConnection]
    # [IntrusionDetection] -> [Installation]
    # [IntrusionDetection] -> [LogStorage]
    graph.add_edge(Edge('intrusiondetection', 'clusterconnection', style='dashed'))
    graph.add_edge(Edge('intrusiondetection', 'installation'))
    graph.add_edge(Edge('intrusiondetection', 'logstorage'))
    # [LogCollector] --> [ClusterConnection]
    # [LogCollector] -> [Installation]
    # [LogCollector] -> [LogStorage]
    graph.add_edge(Edge('logcollector', 'clusterconnection', label='AdditionalStores', style='dashed'))
    graph.add_edge(Edge('logcollector', 'installation'))
    graph.add_edge(Edge('logcollector', 'logstorage'))
    # [LogStorage] -> [Authentication]
    # [LogStorage] -> [ClusterConnection]
    # [LogStorage] -> [Installation]
    graph.add_edge(Edge('logstorage', 'authentication'))
    graph.add_edge(Edge('logstorage', 'clusterconnection', style='dashed'))
    graph.add_edge(Edge('logstorage', 'installation'))
    # [Manager] -> [Authentication]
    # [Manager] -> [ClusterConnection]
    # [Manager] -> [Compliance]
    # [Manager] -> [Installation]
    # [Manager] -> [LogStorage]
    graph.add_edge(Edge('manager', 'authentication'))
    graph.add_edge(Edge('manager', 'clusterconnection', style='dashed'))
    graph.add_edge(Edge('manager', 'compliance'))
    graph.add_edge(Edge('manager', 'installation'))
    graph.add_edge(Edge('manager', 'logstorage'))
    # [Monitor] -> [Authentication]
    graph.add_edge(Edge('monitor', 'authentication'))
    # [Monitor] -> [Installation]
    graph.add_edge(Edge('monitor', 'installation'))

    graph.write_svg('controller-dependency-graph.svg')


if __name__ == '__main__':
    main()
