# 😊 coding_test
> 프로그래머스: 코딩 테스트 준비

# Category
- [😊 coding\_test](#-coding_test)
- [Category](#category)
  - [Common](#common)
  - [Hash](#hash)
  - [Stack/Queue](#stackqueue)
  - [Heap](#heap)
  - [Sort](#sort)
  - [Exhaustive Search](#exhaustive-search)
  - [Greedy](#greedy)
  - [Dynamic Programming](#dynamic-programming)
  - [DFS/BFS](#dfsbfs)
  - [Binary Search](#binary-search)
  - [Graph](#graph)


## Common
- itertools: product, permuations, combinations
- collections.Counter
## Hash
- Use Dictionary
## Stack/Queue
- Use List
- Use deque(collections.deque)
## Heap
- Use heqpq
## Sort
- built-in sort
## Exhaustive Search
- brute-force
## Greedy
## Dynamic Programming
## DFS/BFS
- dfs
```py
def dfs_recursive(graph, start, visited = []):
    visited.append(start)
 
    for node in graph[start]:
        if node not in visited:
            dfs_recursive(graph, node, visited)
    return visited
```
- bfs
```py
from collections import deque

def solution(n, wires):
    answer = int(1e9)
    
    graph = [[] for _ in range(n+1)]
    for wire in wires:
        graph[wire[0]].append(wire[1])
        graph[wire[1]].append(wire[0])
    
    def bfs(s, endPoint):
        visited = [0] * (n+1)
        visited[s] = 1
        q = deque()
        q.append(s)
        
        cnt = 1

        while q:
            x = q.popleft()

            for node in graph[x]:
                if node != endPoint:
                    if not visited[node]:
                        q.append(node)
                        visited[node] = 1
                        cnt += 1
        return cnt
    
    for i in range(1, n + 1):
        for node in graph[i]:
            a = bfs(i, node)
            b = bfs(node, i)
            answer = min(answer, abs(a-b))
    print(answer)
    return answer

solution(9, [[1,3],[2,3],[3,4],[4,5],[4,6],[4,7],[7,8],[7,9]])
```
## Binary Search
## Graph