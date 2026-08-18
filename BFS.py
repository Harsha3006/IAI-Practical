tree = {
    'A': ['B', 'C', 'D'],
    'C': ['E', 'F'],
    'F': ['I', 'G'],
    'D': ['H']
}

start = 'A'
goal = 'G'

queue = [[start]]

while queue:
    path = queue.pop(0)
    current = path[-1]

    if current == goal:
        print("BFS Path:", end=" ")
        for node in path:
            print(node, end=" ")
        print("\nGoal Reached!")
        break

    for child in tree.get(current, []):
        new_path = path + [child]
        queue.append(new_path)