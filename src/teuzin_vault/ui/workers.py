"""Workers simples para manter operações de arquivo fora da thread da UI."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from PySide6.QtCore import QObject, QRunnable, Signal, Slot


class WorkerSignals(QObject):
    """Sinais emitidos por uma operação executada em background."""

    finished = Signal(object)
    failed = Signal(str)


class FunctionWorker(QRunnable):
    """Executa uma função sem bloquear a interface gráfica."""

    def __init__(self, function: Callable[[], Any]) -> None:
        super().__init__()
        self._function = function
        self.signals = WorkerSignals()

    @Slot()
    def run(self) -> None:
        try:
            result = self._function()
        except Exception as exc:
            message = str(exc).strip() or type(exc).__name__
            self.signals.failed.emit(message)
        else:
            self.signals.finished.emit(result)
