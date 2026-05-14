# 导入所需库
import pandas as pd
import numpy as np
from math import sqrt
import random

# 设置随机种子，保证每次运行数据固定不变
np.random.seed(2026)
random.seed(2026)

# ===================== 1. 扩充数据集：15个用户 + 10道菜品 =====================
user_list = [f"用户{i}" for i in range(1, 16)]  # 用户1 ~ 用户15
dish_list = [
    "麻婆豆腐", "水煮鱼", "鱼香肉丝", "番茄炒蛋", "红烧肉",
    "宫保鸡丁", "糖醋排骨", "回锅肉", "酸辣土豆丝", "蒜蓉西兰花"
]

# 生成15行10列随机评分矩阵：1~5分，30%概率为NaN（未评分）
rating_matrix = []
for _ in range(len(user_list)):
    row = []
    for _ in range(len(dish_list)):
        # 30%概率空缺，70%随机1-5分
        if random.random() < 0.3:
            row.append(np.nan)
        else:
            row.append(random.randint(1, 5))
    rating_matrix.append(row)

# 构建DataFrame
df = pd.DataFrame(rating_matrix, columns=dish_list, index=user_list)
print("===== 基于用户协同过滤 菜品推荐系统 =====")
print(f"用户总数：{len(user_list)}  菜品总数：{len(dish_list)}")
print("可用用户ID：用户1 ~ 用户15\n")

# ===================== 2. 计算用户间皮尔逊相似度 =====================
def calc_user_similarity(user1, user2):
    # 取出两个用户评分
    u1 = df.loc[user1]
    u2 = df.loc[user2]
    # 取出两人共同评分过的菜品
    common = df.loc[[user1, user2]].dropna(axis=1).columns
    if len(common) == 0:
        return 0

    r1 = df.loc[user1, common]
    r2 = df.loc[user2, common]

    n = len(common)
    sum1 = r1.sum()
    sum2 = r2.sum()
    sum1_sq = (r1 ** 2).sum()
    sum2_sq = (r2 ** 2).sum()
    p_sum = (r1 * r2).sum()

    numerator = p_sum - (sum1 * sum2 / n)
    denominator = sqrt((sum1_sq - sum1 ** 2 / n) * (sum2_sq - sum2 ** 2 / n))
    if denominator == 0:
        return 0
    return numerator / denominator

# ===================== 3. 用户协同过滤推荐核心 =====================
def collaborative_filtering_recommend(target_user, top_n=3):
    # 所有其他用户
    other_users = [u for u in df.index if u != target_user]
    # 计算相似度
    sim_dict = {u: calc_user_similarity(target_user, u) for u in other_users}
    # 按相似度降序
    sorted_sim = sorted(sim_dict.items(), key=lambda x: x[1], reverse=True)

    # 目标用户未评分的菜品
    unrated_dishes = df.loc[target_user].isna()
    dish_score = {}
    total_sim = 0

    # 加权预测评分
    for user, sim in sorted_sim:
        if sim <= 0:
            continue
        total_sim += sim
        for dish, score in df.loc[user].dropna().items():
            if unrated_dishes[dish]:
                dish_score[dish] = dish_score.get(dish, 0) + sim * score

    # 归一化
    if total_sim > 0:
        for d in dish_score:
            dish_score[d] /= total_sim

    # 排序取前N
    sorted_dish = sorted(dish_score.items(), key=lambda x: x[1], reverse=True)
    real_cnt = min(top_n, len(sorted_dish))
    return [d for d, s in sorted_dish[:real_cnt]], real_cnt

# ===================== 4. 交互式自定义输入 =====================
if __name__ == '__main__':
    # 输入用户ID
    while True:
        target = input("请输入要推荐的用户ID：")
        if target in df.index:
            break
        print("❌ 用户不存在！请输入：用户1 ~ 用户15\n")

    # 输入推荐数量
    while True:
        try:
            num = input("请输入推荐菜品数量(默认3)：").strip()
            num = int(num) if num else 3
            if num > 0:
                break
            print("❌ 请输入大于0的数字\n")
        except ValueError:
            print("❌ 输入格式错误，请输入数字\n")

    # 生成推荐
    rec_list, real_num = collaborative_filtering_recommend(target, num)
    print(f"\n✅ 为【{target}】推荐 {real_num} 道适合的菜品：")
    print(rec_list)