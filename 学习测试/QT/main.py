import sys
from PySide6.QtWidgets import QApplication, QWidget, QPushButton, QVBoxLayout

# 槽函数
def hello():
    print("按钮被点击了！")

app = QApplication(sys.argv)
win = QWidget()
win.setWindowTitle("信号槽基础")

btn = QPushButton("点我")
# 绑定：按钮点击信号 → hello函数
btn.clicked.connect(hello)

lay = QVBoxLayout()
lay.addWidget(btn)
win.setLayout(lay)

win.show()
sys.exit(app.exec())