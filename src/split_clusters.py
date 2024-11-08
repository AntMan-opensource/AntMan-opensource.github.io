import json
from collections import defaultdict


def build_graph(nodes, edges):
    graph = defaultdict(list)
    for edge in edges:
        u, v = edge
        graph[u].append(v)
        graph[v].append(u)
    return graph


def find_connected_components(graph, nodes):
    visited = set()
    connected_components = []

    for node in nodes:
        if node not in visited:
            component = []
            stack = [node]
            while stack:
                current = stack.pop()
                if current not in visited:
                    visited.add(current)
                    component.append(current)
                    stack.extend(graph[current])
            connected_components.append(component)
    return connected_components


def split_clusters(graph):
    clusters = {}
    clusters["pre"] = []
    clusters["post"] = []

    for cluster in graph:
        pre_graph = cluster["pre"]
        nodes = cluster["pre"]["nodes"]
        edges = cluster["pre"]["edges"]
        node_edge = build_graph(nodes, edges)
        connected_components = find_connected_components(node_edge, nodes)
        for connected_component in connected_components:
            pre_cluster = {}
            pre_cluster["nodes"] = []
            pre_cluster["edges"] = []
            pre_cluster["node_dicts"] = {}

            for node in connected_component:
                if (
                    node not in pre_graph["node_dicts"].keys()
                    and str(node) not in pre_graph["node_dicts"].keys()
                ):
                    continue
                pre_cluster["nodes"].append(node)
                for edge in edges:
                    if edge[0] == node:
                        pre_cluster["edges"].append(edge)
                pre_cluster["node_dicts"][node] = pre_graph["node_dicts"][str(node)]

            clusters["pre"].append(pre_cluster)

        post_graph = cluster["post"]
        nodes = cluster["post"]["nodes"]
        edges = cluster["post"]["edges"]
        node_edge = build_graph(nodes, edges)
        connected_components = find_connected_components(node_edge, nodes)
        for connected_component in connected_components:
            post_cluster = {}
            post_cluster["nodes"] = []
            post_cluster["edges"] = []
            post_cluster["node_dicts"] = {}

            for node in connected_component:
                if (
                    node not in post_graph["node_dicts"].keys()
                    and str(node) not in post_graph["node_dicts"].keys()
                ):
                    continue
                post_cluster["nodes"].append(node)
                for edge in edges:
                    if edge[0] == node:
                        post_cluster["edges"].append(edge)
                post_cluster["node_dicts"][node] = post_graph["node_dicts"][str(node)]

            clusters["post"].append(post_cluster)

    return clusters


if __name__ == "__main__":
    fp = open(
        "E:\\workspace\\AntMan-opensource.github.io\\src\\hungarian\\target\\389ds@@389-ds-base-389-ds-base-1.4.3.1\\CVE-2020-35518\\graph_clusters.json"
    )
    cluster = json.load(fp)
    fp.close()
    clusters = split_clusters(cluster)
    print(clusters)
    fp = open(
        "E:\\workspace\\AntMan-opensource.github.io\\src\\hungarian\\target\\389ds@@389-ds-base-389-ds-base-1.4.3.1\\CVE-2020-35518\\graph_clusters.json",
        "w",
    )
    json.dump(clusters, fp, indent=4)
    fp.close()
