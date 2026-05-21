import pandas as pd
import numpy as np
import random
import os
import sys
from scipy.sparse import csr_matrix
from sklearn.metrics.pairwise import cosine_similarity

# ===================== 适配EXE全局路径 =====================
def get_base_path():
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))

BASE_PATH = get_base_path()
CSV_PATH = os.path.join(BASE_PATH, "food_data.csv")

# ===================== 核心：30道菜品库 =====================
ALL_FOODS = [
    "鱼香肉丝","宫保鸡丁","麻婆豆腐","水煮鱼","红烧肉","番茄炒蛋",
    "糖醋里脊","青椒土豆丝","回锅肉","辣子鸡","酸菜鱼","地三鲜",
    "京酱肉丝","葱爆羊肉","干锅菜花","香菇青菜","蒜蓉西兰花","土豆烧牛肉",
    "红烧排骨","白切鸡","烧茄子","干煸豆角","韭菜炒鸡蛋","酸辣土豆丝",
    "手撕包菜","蚝油生菜","木耳炒肉","冬瓜排骨汤","西红柿鸡蛋汤","紫菜蛋花汤"
]
TOTAL_FOOD_NUM = 30  # 总菜品数：30道
MAX_EAT_NUM = 29     # 每人最多吃29道 → 强制至少剩1道未品尝

# ===================== 生成合规数据集（一次生成永久使用） =====================
def init_dataset():
    if os.path.exists(CSV_PATH):
        print("✅ 读取本地菜品数据集成功")
        return pd.read_csv(CSV_PATH, encoding="utf-8")

    print("🔶 首次运行，生成30道菜品大规模合规数据集...")
    random.seed(42)
    np.random.seed(42)

    user_range = range(1, 2001)  # 2000个用户
    data_list = []

    for uid in user_range:
        # 随机品尝 1~29 道菜，必定留至少1道未品尝
        eat_count = random.randint(1, MAX_EAT_NUM)
        user_eat_foods = random.sample(ALL_FOODS, eat_count)
        # 随机评分1-5分
        for food in user_eat_foods:
            score = random.randint(1, 5)
            data_list.append({"user_id": uid, "food_name": food, "rating": score})

    df = pd.DataFrame(data_list)
    df.to_csv(CSV_PATH, index=False, encoding="utf-8")
    print(f"✅ 数据已保存至：{CSV_PATH}")
    print(f"📊 总用户数：2000 | 总菜品数：{TOTAL_FOOD_NUM}道")
    print(f"💡 规则：每位用户最多品尝29道菜，全员至少留有1道未品尝菜品")
    return df

# ===================== 数据清洗 & 优化矩阵构建 =====================
def process_data(df):
    df = df.dropna()
    df = df[(df["rating"] >= 1) & (df["rating"] <= 5)]
    # 构建用户-菜品评分矩阵
    rating_matrix = df.pivot_table(index="user_id", columns="food_name", values="rating", fill_value=0)
    # 稀疏矩阵+余弦相似度计算
    item_sparse = csr_matrix(rating_matrix.values).T
    item_sim = cosine_similarity(item_sparse)
    sim_df = pd.DataFrame(item_sim, index=rating_matrix.columns, columns=rating_matrix.columns)
    print(f"✅ 系统初始化完成！有效用户：{rating_matrix.shape[0]} 个\n")
    return rating_matrix, sim_df

# ===================== 协同过滤推荐算法（动态推荐数量 核心修复） =====================
def recommend(user_id, matrix, sim_df, top_n=5):
    # 新用户/不存在用户 → 冷启动热门推荐
    if user_id not in matrix.index:
        hot = matrix.mean().sort_values(ascending=False).head(top_n)
        res = "\n🆕 暂无该用户记录，为您推荐热门高分菜品：\n"
        for i, (d, s) in enumerate(hot.items(), 1):
            res += f"{i}. {d} | 平均评分：{s:.1f}\n"
        return res

    user = matrix.loc[user_id]
    rated = user[user > 0]    # 已品尝菜品
    unrated = user[user == 0] # 未品尝菜品（必定存在）

    # 计算推荐得分
    scores = {}
    for dish in unrated.index:
        score = sum(sim_df.loc[dish, r] * s for r, s in rated.items())
        scores[dish] = score

    # 🔥 核心修复：动态取实际可推荐数量（最少1道，最多5道）
    actual_top = min(top_n, len(unrated))
    top = sorted(scores.items(), key=lambda x: x[1], reverse=True)[:actual_top]
    
    # 动态显示实际推荐数量
    res = f"\n🎯 用户【{user_id}】专属菜品推荐 Top-{actual_top}：\n"
    for i, (d, s) in enumerate(top, 1):
        res += f"{i}. {d} | 推荐分值：{s:.2f}\n"
    return res

# ===================== 交互式输入用户ID =====================
def input_user_id():
    while True:
        tip = input("\n请输入查询用户ID (输入 q 退出程序)：").strip()
        if tip.lower() == "q":
            print("👋 程序正常退出！")
            sys.exit(0)
        try:
            return int(tip)
        except:
            print("❌ 输入格式错误，请输入纯数字用户ID！")

# ===================== 主程序 =====================
if __name__ == "__main__":
    print("="*60)
    print("        🍽️  菜品智能推荐系统（优化协同过滤版）")
    print("="*60)

    # 初始化数据
    data_df = init_dataset()
    rating_mat, sim_mat = process_data(data_df)

    # 循环交互推荐
    while True:
        target_uid = input_user_id()
        print(recommend(target_uid, rating_mat, sim_mat))
        print("-"*50)