from collections import deque
import heapq

# System graph: adjacency list
graph = {
    'Internet': ['WebServer'],
    'WebServer': ['Database', 'FileStorage', 'AdminPanel'],
    'Database': [],
    'FileStorage': [],
    'AdminPanel': ['Database']
}

def bfs(start='Internet'):
    """
    Breadth First Search to explore vulnerable systems.
    Returns list of reachable nodes.
    """
    visited = set()
    queue = deque([start])
    visited.add(start)
    vulnerable = []

    while queue:
        node = queue.popleft()
        vulnerable.append(node)
        for neighbor in graph.get(node, []):
            if neighbor not in visited:
                visited.add(neighbor)
                queue.append(neighbor)

    return vulnerable

def dfs(start='Internet', path=None):
    """
    Depth First Search to find worst-case attack paths.
    Returns the deepest path.
    """
    if path is None:
        path = []
    path = path + [start]
    if not graph.get(start):
        return path
    longest_path = path
    for node in graph.get(start, []):
        if node not in path:
            new_path = dfs(node, path)
            if len(new_path) > len(longest_path):
                longest_path = new_path
    return longest_path

def a_star_defense(threat_score):
    """
    A* Search for optimal defense action.
    Actions: name, cost, reduction
    """
    actions = [
        {"name": "Alert Admin", "cost": 1, "reduction": 1},
        {"name": "Block IP", "cost": 2, "reduction": 2},
        {"name": "Disable Login", "cost": 3, "reduction": 3},
        {"name": "Restart Server", "cost": 4, "reduction": 4}
    ]

    best_action = None
    min_f = float('inf')

    for action in actions:
        new_threat = max(0, threat_score - action["reduction"])
        g = action["cost"]
        h = new_threat
        f = g + h
        if f < min_f:
            min_f = f
            best_action = action["name"]

    return best_action