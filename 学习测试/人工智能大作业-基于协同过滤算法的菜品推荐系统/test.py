# 导入所需库
import pandas as pd
import numpy as np
from math import sqrt
import os
import sys

# ===================== 【修复】兼容PY和EXE，自动在程序同目录创建Excel =====================
def get_real_path():
    # 获取程序真实路径（PY运行取代码目录，EXE运行取EXE所在目录）
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    else:
        return os.path.dirname(os.path.abspath(__file__))

# 自动定位文件夹 + Excel文件路径
current_folder = get_real_path()
excel_file = os.path.join(current_folder, "dish_ratings.xlsx")

# 自动创建数据集（严格包含用户ID列，永不报错）
if not os.path.exists(excel_file):
    print("📌 自动创建数据集...")
    data = {
        "用户ID": [f"用户{i}" for i in range(1, 16)],
        "麻婆豆腐": [5,4,np.nan,2,3,5,4,np.nan,2,5,3,4,np.nan,5,2],
        "水煮鱼": [4,np.nan,3,1,2,np.nan,5,3,4,2,5,np.nan,2,3,4],
        "鱼香肉丝": [3,5,4,np.nan,4,3,2,5,np.nan,4,4,2,5,np.nan,3],
        "番茄炒蛋": [2,3,5,4,np.nan,4,3,2,5,np.nan,2,5,3,4,np.nan],
        "红烧肉": [np.nan,2,4,5,3,np.nan,5,4,3,2,np.nan,3,5,2,5],
        "宫保鸡丁": [4,3,5,2,np.nan,5,np.nan,3,4,5,2,5,np.nan,3,4],
        "糖醋排骨": [5,4,np.nan,3,5,2,4,5,np.nan,3,5,2,4,5,np.nan],
    }
    # 写入Excel，保证格式正确
    pd.DataFrame(data).to_excel(excel_file, index=False)

# ===================== 读取数据 =====================
df = pd.read_excel(excel_file)
# 强制设置索引
if "用户ID" in df.columns:
    df = df.set_index("用户ID")
else:
    df.index = [f"用户{i}" for i in range(1, 16)]

# ===================== 协同过滤算法 =====================
def calc_user_similarity(user1, user2):
    u1 = df.loc[user1].dropna()
    u2 = df.loc[user2].dropna()
    common = list(set(u1.index) & set(u2.index))
    if len(common) == 0:
        return 0
    x = df.loc[user1, common]
    y = df.loc[user2, common]
    n = len(x)
    num = np.sum(x*y) - (np.sum(x)*np.sum(y)/n)
    den = np.sqrt((np.sum(x**2)-(np.sum(x)**2)/n) * (np.sum(y**2)-(np.sum(y)**2)/n))
    return num/den if den != 0 else 0

def recommend(target_user, top_n=3):
    others = [u for u in df.index if u != target_user]
    sims = {u: calc_user_similarity(target_user, u) for u in others}
    sims = sorted(sims.items(), key=lambda x:x[1], reverse=True)
    
    unrated = df.loc[target_user].isna()
    scores = {}
    total_sim = 0
    
    for user, sim in sims:
        if sim <= 0: continue
        total_sim += sim
        for dish, rate in df.loc[user].dropna().items():
            if unrated[dish]:
                scores[dish] = scores.get(dish, 0) + sim*rate
    
    if total_sim > 0:
        for k in scores: scores[k] /= total_sim
    
    res = sorted(scores.items(), key=lambda x:x[1], reverse=True)[:top_n]
    return [d for d,_ in res]

# ===================== 交互运行 =====================
print("===== 基于用户协同过滤的菜品推荐系统 =====")
print(f"用户列表：{list(df.index)}")

while True:
    uid = input("\n请输入用户ID：")
    if uid in df.index: break
    print("❌ 用户不存在")

num = input("请输入推荐数量(默认1)：")
num = int(num) if num.strip() else 1
result = recommend(uid, num)

print(f"\n✅ 为【{uid}】推荐菜品：{result}")
input("\n按回车键退出程序...")