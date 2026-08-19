graph = {
    'A': ['B', 'C', 'D'],
    'B': [],
    'C': ['E', 'F'],
    'D': ['H'],
    'E': [],
    'F': ['I', 'G'],
    'G': [],
    'H': [],
    'I': []
}

start = 'A'
goal = 'G'

visited = []

def dfs(node):
    if node in visited:
        return

    print(node, end=" ")
    visited.append(node)

    if node == goal:
        print("\nGoal Found!")
        return True

    for child in graph[node]:
        if dfs(child):
            return True

    return False

dfs(start)
