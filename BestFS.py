tree = {
    'A': ['B', 'C', 'D'],
    'C': ['E', 'F'],
    'F': ['I', 'G'],
    'D': ['H']
}

h = {
    'A': 15,
    'B': 13,
    'C': 10,
    'D': 14,
    'E': 11,
    'F': 8,
    'I': 4,
    'H': 9,
    'G': 0
}

current = 'A'

path = [current]
print("Best First Search Path:", current, end=" ")

while current != 'G':
    children = tree.get(current, [])

    if not children:
        print("\nGoal not found!")
        break

    current = min(children, key=lambda node: h[node])

    path.append(current)
    print(f"-> {current}", end=" ")

print("\nGoal Reached!")