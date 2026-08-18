tree = {
    'A': ['B', 'C', 'D'],
    'C': ['E', 'F'],
    'F': ['I', 'G'],
    'D': ['H']
}

current = 'A'
goal = 'G'

path = []

def dfs(node):
    path.append(node)

    if node == goal:
        return True

    for child in tree.get(node, []):
        if dfs(child):
            return True

    path.pop()
    return False

dfs(current)

print("DFS Path:", end=" ")
for node in path:
    print(node, end=" ")

print("\nGoal Reached!")