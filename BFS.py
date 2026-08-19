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

queue = [start]
visited = []

while queue:
    node = queue.pop(0)

    if node not in visited:
        print(node, end=" ")
        visited.append(node)

        if node == goal:
            print("\nGoal Found!")
            break

        for child in graph[node]:
            if child not in visited:
                queue.append(child)
