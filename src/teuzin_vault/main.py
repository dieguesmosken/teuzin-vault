"""Ponto de entrada do Teuzin Vault."""

import sys

from PySide6.QtWidgets import QApplication, QLabel, QMainWindow


class MainWindow(QMainWindow):
    """Janela principal inicial."""

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("Teuzin Vault")
        self.resize(900, 600)
        self.setCentralWidget(
            QLabel("Teuzin Vault — estrutura inicial do projeto")
        )


def main() -> int:
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
