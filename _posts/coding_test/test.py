from itertools import product

if __name__ == "__main__":
    dic1 = list(product(["A", "E", "I", "O", "U"], repeat = 1))
    dic2 = list(product(["A", "E", "I", "O", "U"], repeat = 2))
    dic3 = list(product(["A", "E", "I", "O", "U"], repeat = 3))
    dic4 = list(product(["A", "E", "I", "O", "U"], repeat = 4))
    dic5 = list(product(["A", "E", "I", "O", "U"], repeat = 5))

    all_dic = sorted(dic1 + dic2 + dic3 + dic4 + dic5)
    print(all_dic)