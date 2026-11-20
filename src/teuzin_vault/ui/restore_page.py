"""Fluxo de restauração de arquivos TVLT pela interface desktop."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QThreadPool, Signal
from PySide6.QtWidgets import (
    QFileDialog,
    QFormLayout,
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QProgressBar,
    QSpinBox,
    QVBoxLayout,
    QWidget,
    QComboBox,
)

from teuzin_vault.core.file_operations import restore_container_file
from teuzin_vault.fido2.authenticator import get_hmac_secret
from teuzin_vault.ui.restore_support import (
    decode_recovery_secret,
    default_credential_metadata_path,
    fido2_authentication_material,
    read_container_header,
)
from teuzin_vault.ui.workers import FunctionWorker


GIB = 1024 ** 3


class RestorePage(QWidget):
    """Restaura um arquivo de um cofre existente, sem bloquear a UI."""

    restored = Signal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._pool = QThreadPool(self)
        self._worker: FunctionWorker | None = None
        self._secret_buffer: bytearray | None = None
        self._browse_buttons: list[QPushButton] = []

        self._build_ui()
        self._update_unlock_fields()

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(30, 26, 30, 26)
        root.setSpacing(18)

        title = QLabel("Restaurar arquivo")
        title.setObjectName("pageTitle")
        subtitle = QLabel(
            "Desbloqueie um cofre TVLT e restaure o arquivo original. "
            "O arquivo de origem não será alterado."
        )
        subtitle.setObjectName("mutedText")
        subtitle.setWordWrap(True)
        root.addWidget(title)
        root.addWidget(subtitle)

        files_group = QGroupBox("Arquivos")
        files_form = QFormLayout(files_group)
        files_form.setFieldGrowthPolicy(
            QFormLayout.FieldGrowthPolicy.ExpandingFieldsGrow
        )

        source_row = QHBoxLayout()
        self.container_edit = QLineEdit()
        self.container_edit.setPlaceholderText("Selecione um arquivo .tvault")
        source_button = QPushButton("Procurar…")
        source_button.clicked.connect(self._browse_container)
        self._browse_buttons.append(source_button)
        source_row.addWidget(self.container_edit, 1)
        source_row.addWidget(source_button)
        files_form.addRow("Cofre:", self._wrap_layout(source_row))

        destination_row = QHBoxLayout()
        self.destination_edit = QLineEdit()
        self.destination_edit.setPlaceholderText(
            "Escolha onde salvar o arquivo restaurado"
        )
        destination_button = QPushButton("Salvar como…")
        destination_button.clicked.connect(self._browse_destination)
        self._browse_buttons.append(destination_button)
        destination_row.addWidget(self.destination_edit, 1)
        destination_row.addWidget(destination_button)
        files_form.addRow("Destino:", self._wrap_layout(destination_row))
        root.addWidget(files_group)

        unlock_group = QGroupBox("Desbloqueio")
        unlock_form = QFormLayout(unlock_group)
        self.method_combo = QComboBox()
        self.method_combo.addItems(
            [
                "Autenticador FIDO2 — PIN ou biometria (Windows)",
                "Segredo de recuperação",
            ]
        )
        self.method_combo.currentIndexChanged.connect(self._update_unlock_fields)
        unlock_form.addRow("Método:", self.method_combo)

        metadata_row = QHBoxLayout()
        self.metadata_edit = QLineEdit(str(default_credential_metadata_path()))
        self.metadata_edit.setPlaceholderText(
            "Arquivo JSON com metadados públicos da credencial"
        )
        metadata_button = QPushButton("Procurar…")
        metadata_button.clicked.connect(self._browse_metadata)
        self._browse_buttons.append(metadata_button)
        metadata_row.addWidget(self.metadata_edit, 1)
        metadata_row.addWidget(metadata_button)
        self.metadata_label = QLabel("Metadados da credencial:")
        self._metadata_row_widget = self._wrap_layout(metadata_row)
        unlock_form.addRow(
            self.metadata_label,
            self._metadata_row_widget,
        )

        self.uv_note = QLabel(
            "O Windows poderá solicitar que você toque na Yubico e informe "
            "o PIN ou use a biometria configurada."
        )
        self.uv_note.setObjectName("mutedText")
        self.uv_note.setWordWrap(True)
        unlock_form.addRow("", self.uv_note)

        self.recovery_edit = QLineEdit()
        self.recovery_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.recovery_edit.setPlaceholderText("64 caracteres hexadecimais")
        self.recovery_label = QLabel("Segredo de recuperação:")
        unlock_form.addRow(self.recovery_label, self.recovery_edit)
        root.addWidget(unlock_group)

        limits_group = QGroupBox("Limite de restauração")
        limits_form = QFormLayout(limits_group)
        self.max_size_spin = QSpinBox()
        self.max_size_spin.setRange(1, 4096)
        self.max_size_spin.setValue(4)
        self.max_size_spin.setSuffix(" GiB")
        limits_form.addRow("Tamanho máximo do arquivo:", self.max_size_spin)
        limit_note = QLabel(
            "O limite evita que um cofre inesperado tente produzir uma saída "
            "excessivamente grande. Aumente-o se o arquivo original for maior."
        )
        limit_note.setObjectName("mutedText")
        limit_note.setWordWrap(True)
        limits_form.addRow("", limit_note)
        root.addWidget(limits_group)

        controls = QHBoxLayout()
        self.status_label = QLabel("Pronto para restaurar.")
        self.status_label.setObjectName("mutedText")
        controls.addWidget(self.status_label, 1)

        self.progress = QProgressBar()
        self.progress.setRange(0, 1)
        self.progress.setValue(0)
        self.progress.setTextVisible(False)
        self.progress.setFixedWidth(130)
        self.progress.hide()
        controls.addWidget(self.progress)

        self.restore_button = QPushButton("Restaurar arquivo")
        self.restore_button.setObjectName("primaryButton")
        self.restore_button.clicked.connect(self._start_restore)
        controls.addWidget(self.restore_button)
        root.addLayout(controls)
        root.addStretch(1)

    @staticmethod
    def _wrap_layout(layout: QHBoxLayout) -> QWidget:
        wrapper = QWidget()
        wrapper.setLayout(layout)
        return wrapper

    def _browse_container(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Selecionar cofre",
            "",
            "Cofres Teuzin Vault (*.tvault);;Todos os arquivos (*.*)",
        )
        if path:
            self.container_edit.setText(path)
            source = Path(path)
            # O formato V1 não armazena o nome/extensão do arquivo original.
            suggested = source.with_name(f"{source.stem}-restaurado")
            self.destination_edit.setText(str(suggested))

    def _browse_destination(self) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Salvar arquivo restaurado",
            self.destination_edit.text(),
            "Todos os arquivos (*.*)",
        )
        if path:
            self.destination_edit.setText(path)

    def _browse_metadata(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Selecionar metadados públicos da credencial",
            self.metadata_edit.text(),
            "Arquivo JSON (*.json);;Todos os arquivos (*.*)",
        )
        if path:
            self.metadata_edit.setText(path)

    def _update_unlock_fields(self) -> None:
        use_fido = self.method_combo.currentIndex() == 0
        self.metadata_label.setVisible(use_fido)
        self.metadata_edit.setVisible(use_fido)
        self.uv_note.setVisible(use_fido)
        self.recovery_label.setVisible(not use_fido)
        self.recovery_edit.setVisible(not use_fido)
        self._metadata_row_widget.setVisible(use_fido)

    def _set_busy(self, busy: bool, message: str) -> None:
        self.restore_button.setEnabled(not busy)
        self.container_edit.setEnabled(not busy)
        self.destination_edit.setEnabled(not busy)
        self.method_combo.setEnabled(not busy)
        self.metadata_edit.setEnabled(not busy)
        self.recovery_edit.setEnabled(not busy)
        self.max_size_spin.setEnabled(not busy)
        for button in self._browse_buttons:
            button.setEnabled(not busy)
        self.status_label.setText(message)

        if busy:
            self.progress.setRange(0, 0)
            self.progress.show()
        else:
            self.progress.setRange(0, 1)
            self.progress.setValue(0)
            self.progress.hide()

    def is_busy(self) -> bool:
        return self._worker is not None

    def _start_restore(self) -> None:
        source_text = self.container_edit.text().strip()
        destination_text = self.destination_edit.text().strip()

        if not source_text or not destination_text:
            QMessageBox.warning(
                self,
                "Arquivos necessários",
                "Selecione o cofre e o destino do arquivo restaurado.",
            )
            return

        source = Path(source_text)
        destination = Path(destination_text)

        if not source.is_file():
            QMessageBox.warning(
                self,
                "Cofre não encontrado",
                "Selecione um arquivo de cofre existente.",
            )
            return

        if destination.exists():
            QMessageBox.warning(
                self,
                "Destino já existe",
                "Para evitar sobrescrever arquivos, escolha um destino que ainda não exista.",
            )
            return

        try:
            parsed_header = read_container_header(source)
            max_output_size = self.max_size_spin.value() * GIB

            if self.method_combo.currentIndex() == 0:
                metadata_path = Path(self.metadata_edit.text().strip())
                if not metadata_path.is_file():
                    raise FileNotFoundError(
                        "Selecione o arquivo local de metadados da credencial FIDO2."
                    )

                hmac_salt, credential_id = fido2_authentication_material(
                    parsed_header
                )

                def operation():
                    fido_secret = get_hmac_secret(
                        metadata_path,
                        hmac_salt,
                        expected_credential_id=credential_id,
                    )
                    return restore_container_file(
                        source,
                        destination,
                        max_output_size=max_output_size,
                        fido2_hmac_secret=fido_secret,
                    )

                status_message = (
                    "Aguardando autenticação FIDO2. Siga a solicitação do Windows."
                )
            else:
                self._secret_buffer = bytearray(
                    decode_recovery_secret(self.recovery_edit.text())
                )
                secret_buffer = self._secret_buffer

                def operation():
                    try:
                        return restore_container_file(
                            source,
                            destination,
                            max_output_size=max_output_size,
                            recovery_secret=bytes(secret_buffer),
                        )
                    finally:
                        for index in range(len(secret_buffer)):
                            secret_buffer[index] = 0

                status_message = "Validando o segredo e restaurando o arquivo…"

        except Exception as exc:
            self._secret_buffer = None
            QMessageBox.warning(self, "Não foi possível iniciar", str(exc))
            return

        self._set_busy(True, status_message)
        self._worker = FunctionWorker(operation)
        self._worker.signals.finished.connect(self._on_restore_finished)
        self._worker.signals.failed.connect(self._on_restore_failed)
        self._pool.start(self._worker)

    def _on_restore_finished(self, result: object) -> None:
        self._worker = None
        self._secret_buffer = None
        self.recovery_edit.clear()
        self._set_busy(False, "Restauração concluída.")
        destination = self.destination_edit.text().strip()
        self.restored.emit(destination)

        original_bytes = getattr(result, "original_bytes", None)
        size_message = (
            f"\nTamanho restaurado: {original_bytes:,} bytes."
            if isinstance(original_bytes, int)
            else ""
        )
        QMessageBox.information(
            self,
            "Arquivo restaurado",
            f"O arquivo foi restaurado e validado com sucesso.\n\n{destination}{size_message}",
        )

    def _on_restore_failed(self, message: str) -> None:
        self._worker = None
        self._secret_buffer = None
        self.recovery_edit.clear()
        self._set_busy(False, "A restauração não foi concluída.")
        QMessageBox.critical(
            self,
            "Falha na restauração",
            f"{message}\n\nO arquivo de destino não foi publicado.",
        )
