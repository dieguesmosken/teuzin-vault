"""Ponto de entrada do Teuzin Vault."""

import sys

from PySide6.QtWidgets import QApplication

from teuzin_vault.ui.main_window import MainWindow


def main() -> int:
    app = QApplication(sys.argv)
    app.setApplicationName("Teuzin Vault")
    app.setOrganizationName("Teuzin")
    window = MainWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
