graph ={
    'A':{'B':1,'C':4},
    'B':{'D':2},
    'C':{'D':1},
    'D':{'G':3},
    'G':{}
}

h={
    'A':6,
    'B':5,
    'C':3,
    'D':2,
    'G':0,
}
start='A'
goal='G'

open_list=[start]
cost={start:0}
path={start:[start]}

while open_list:
    current=min(open_list,key=lambda x:cost[x] + h[x])
    open_list.remove(current)
    
    if current==goal:
        print("A* path:",path[current])
        print("Total cost:",cost[current])
        break
    
    for child,edge_cost in graph[current].items():
        new_cost=cost[current]+edge_cost
        
        if child not in cost or new_cost<cost[child]:
            cost[child]=new_cost
            path[child]=path[current]+[child]
            open_list.append(child)