from itertools import permutations

def solution(k, dungeons):
    max_result = 0
    print("what")
    for i in range(len(dungeons), 0, -1):
        for p in permutations(dungeons, i):
            print(p)
            pirodo = k
            result = 0
            for least, consume in p:
                if pirodo >= least and pirodo >= consume:
                    pirodo -= consume
                    result += 1
            if result > max_result:
                max_result = result
    return max_result

print(solution(80, [[80,20],[50,40],[30,10]]))