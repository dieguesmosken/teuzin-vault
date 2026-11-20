"""Janela principal do Teuzin Vault."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QCloseEvent
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from teuzin_vault.ui.restore_page import RestorePage


class HomePage(QWidget):
    """Página inicial e ponto de entrada para os fluxos disponíveis."""

    def __init__(self, open_restore, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(34, 32, 34, 32)
        layout.setSpacing(22)

        eyebrow = QLabel("TEUZIN VAULT  /  ARQUIVOS SOB SEU CONTROLE")
        eyebrow.setObjectName("eyebrow")
        title = QLabel("Proteção local.\nControle seu.")
        title.setObjectName("heroTitle")
        subtitle = QLabel(
            "Compactação e criptografia com autenticação FIDO2 e recuperação independente."
        )
        subtitle.setObjectName("mutedText")
        subtitle.setWordWrap(True)
        layout.addWidget(eyebrow)
        layout.addWidget(title)
        layout.addWidget(subtitle)

        actions = QHBoxLayout()
        actions.setSpacing(16)
        actions.addWidget(
            self._make_card(
                "Restaurar um arquivo",
                "Abra um cofre .tvault, autentique com sua Yubico ou use o segredo de recuperação.",
                "Abrir restauração",
                open_restore,
                active=True,
            )
        )
        actions.addWidget(
            self._make_card(
                "Criar um cofre",
                "A criação de novos cofres pela interface será conectada na próxima etapa.",
                "Em desenvolvimento",
                None,
                active=False,
            )
        )
        layout.addLayout(actions)

        notice = QLabel(
            "VERSÃO EXPERIMENTAL — mantenha sempre outra cópia dos seus arquivos. "
            "Não use esta versão como único backup."
        )
        notice.setObjectName("notice")
        notice.setWordWrap(True)
        layout.addWidget(notice)
        layout.addStretch(1)

    @staticmethod
    def _make_card(
        title_text: str,
        description: str,
        button_text: str,
        callback,
        *,
        active: bool,
    ) -> QFrame:
        card = QFrame()
        card.setObjectName("actionCard")
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(22, 22, 22, 22)
        card_layout.setSpacing(12)

        title = QLabel(title_text)
        title.setObjectName("cardTitle")
        body = QLabel(description)
        body.setObjectName("mutedText")
        body.setWordWrap(True)
        button = QPushButton(button_text)
        button.setEnabled(active)
        if active:
            button.setObjectName("primaryButton")
            button.clicked.connect(callback)
        else:
            button.setToolTip("Este fluxo ainda está em desenvolvimento.")

        card_layout.addWidget(title)
        card_layout.addWidget(body, 1)
        card_layout.addWidget(button)
        return card


class AboutPage(QWidget):
    """Informações e limites claros da versão atual."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(34, 32, 34, 32)
        layout.setSpacing(14)

        title = QLabel("Sobre o Teuzin Vault")
        title.setObjectName("pageTitle")
        body = QLabel(
            "O Teuzin Vault é um aplicativo desktop local para compactação e proteção "
            "criptográfica de arquivos. Esta versão permite restaurar cofres TVLT V1 "
            "com FIDO2 no Windows (verificação do usuário obrigatória) ou com o segredo "
            "independente de recuperação. O formato atual não guarda o nome ou a extensão "
            "do arquivo original, então escolha o nome correto ao salvar.\n\n"
            "A criação de cofres pela interface, a seleção de pastas e a extração de "
            "múltiplos arquivos ainda estão em desenvolvimento.\n\n"
            "O projeto é experimental e ainda não passou por auditoria independente."
        )
        body.setObjectName("mutedText")
        body.setWordWrap(True)
        body.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        layout.addWidget(title)
        layout.addWidget(body)
        layout.addStretch(1)


class MainWindow(QMainWindow):
    """Janela principal com navegação entre início, restauração e informações."""

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("Teuzin Vault")
        self.resize(1080, 760)
        self.setMinimumSize(900, 650)

        tabs = QTabWidget()
        self.tabs = tabs
        self.restore_page = RestorePage()
        tabs.addTab(
            HomePage(lambda: tabs.setCurrentWidget(self.restore_page)),
            "Início",
        )
        tabs.addTab(self.restore_page, "Restaurar arquivo")
        tabs.addTab(AboutPage(), "Sobre")
        self.setCentralWidget(tabs)

        self.setStyleSheet(
            """
            QMainWindow, QWidget {
                background: #101722;
                color: #edf2f7;
                font-family: "Segoe UI";
                font-size: 10pt;
            }
            QTabWidget::pane {
                border: 1px solid #273445;
                border-radius: 10px;
                top: -1px;
            }
            QTabBar::tab {
                background: #172231;
                color: #aab8c8;
                padding: 12px 22px;
                border: 1px solid #273445;
                border-bottom: none;
                border-top-left-radius: 8px;
                border-top-right-radius: 8px;
                margin-right: 4px;
            }
            QTabBar::tab:selected {
                background: #202f40;
                color: #ffffff;
            }
            QLabel#eyebrow {
                color: #6fd3c2;
                font-size: 9pt;
                font-weight: 700;
                letter-spacing: 1px;
            }
            QLabel#heroTitle {
                font-size: 30pt;
                font-weight: 700;
                color: #ffffff;
            }
            QLabel#pageTitle {
                font-size: 23pt;
                font-weight: 700;
                color: #ffffff;
            }
            QLabel#cardTitle {
                font-size: 15pt;
                font-weight: 700;
            }
            QLabel#mutedText {
                color: #aab8c8;
            }
            QLabel#notice {
                color: #e4c47a;
                background: #29271f;
                border: 1px solid #655535;
                border-radius: 8px;
                padding: 13px;
            }
            QFrame#actionCard, QGroupBox {
                background: #172231;
                border: 1px solid #2a3a4d;
                border-radius: 10px;
            }
            QGroupBox {
                margin-top: 12px;
                padding: 18px 14px 14px 14px;
                font-weight: 700;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 14px;
                padding: 0 6px;
                color: #6fd3c2;
            }
            QLineEdit, QSpinBox, QComboBox {
                background: #0e151f;
                border: 1px solid #35475b;
                border-radius: 6px;
                padding: 9px;
                selection-background-color: #267f79;
            }
            QLineEdit:focus, QSpinBox:focus, QComboBox:focus {
                border: 1px solid #6fd3c2;
            }
            QPushButton {
                background: #253448;
                color: #f3f6fa;
                border: 1px solid #40546b;
                border-radius: 7px;
                padding: 9px 14px;
            }
            QPushButton:hover:enabled {
                background: #30445b;
            }
            QPushButton:disabled {
                color: #728095;
                background: #1a2532;
                border-color: #2b3948;
            }
            QPushButton#primaryButton {
                background: #187f78;
                border: 1px solid #269e95;
                color: #ffffff;
                font-weight: 700;
                padding: 11px 18px;
            }
            QPushButton#primaryButton:hover:enabled {
                background: #20958c;
            }
            QProgressBar {
                background: #0e151f;
                border: 1px solid #35475b;
                border-radius: 4px;
                min-height: 8px;
                max-height: 8px;
            }
            QProgressBar::chunk {
                background: #6fd3c2;
                border-radius: 4px;
            }
            """
        )

    def closeEvent(self, event: QCloseEvent) -> None:
        if self.restore_page.is_busy():
            QMessageBox.warning(
                self,
                "Restauração em andamento",
                "Aguarde a conclusão da restauração antes de fechar o Teuzin Vault.",
            )
            event.ignore()
            return
        event.accept()
