from __future__ import annotations

import threading
import webbrowser
from tkinter import Button, Entry, Frame, Label, StringVar, Tk, messagebox

from .config import DEFAULT_PORT
from .db import get_conn
from .security import verify_password


class DesktopAdminApp:
    def __init__(self) -> None:
        self.root = Tk()
        self.root.title("Guardian LAN - lokální správa")
        self.root.geometry("420x240")
        self.root.resizable(False, False)

        self.username_var = StringVar(value="admin")
        self.password_var = StringVar()
        self.status_var = StringVar(value="Přihlas se pro otevření lokální správy.")

        self._build_ui()

    def _build_ui(self) -> None:
        wrap = Frame(self.root, padx=18, pady=18)
        wrap.pack(fill="both", expand=True)

        Label(wrap, text="Guardian LAN", font=("Segoe UI", 16, "bold")).pack(anchor="w")
        Label(wrap, text="Lokální administrace na tomto počítači", font=("Segoe UI", 10)).pack(anchor="w", pady=(0, 12))

        Label(wrap, text="Uživatelské jméno").pack(anchor="w")
        Entry(wrap, textvariable=self.username_var).pack(fill="x", pady=(0, 10))

        Label(wrap, text="Heslo").pack(anchor="w")
        Entry(wrap, textvariable=self.password_var, show="*").pack(fill="x", pady=(0, 12))

        row = Frame(wrap)
        row.pack(fill="x")
        Button(row, text="Přihlásit a otevřít web", command=self.open_web, width=24).pack(side="left")
        Button(row, text="Zavřít", command=self.root.destroy, width=12).pack(side="right")

        Label(wrap, textvariable=self.status_var, fg="#555").pack(anchor="w", pady=(14, 0))

    def open_web(self) -> None:
        username = self.username_var.get().strip()
        password = self.password_var.get()
        with get_conn() as conn:
            row = conn.execute("SELECT * FROM admins WHERE username = ?", (username,)).fetchone()
        if not row or not verify_password(password, row["password_hash"]):
            messagebox.showerror("Guardian LAN", "Neplatné přihlášení.")
            return
        self.status_var.set("Otevírám lokální webovou správu…")
        threading.Thread(target=lambda: webbrowser.open(f"http://127.0.0.1:{DEFAULT_PORT}/login"), daemon=True).start()
        messagebox.showinfo("Guardian LAN", "Webová správa byla otevřena v prohlížeči.")

    def run(self) -> None:
        self.root.mainloop()


def main() -> None:
    DesktopAdminApp().run()


if __name__ == "__main__":
    main()
