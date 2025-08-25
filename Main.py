import customtkinter as ctk
import secrets
import string
import re
import pyperclip
import math


ctk.set_appearance_mode("Light")
ctk.set_default_color_theme("dark-blue")


class PasswordApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Password Strength Checker & Suggester")
        self.geometry("800x680")
        self.resizable(False, False)

        self.main_frame = ctk.CTkFrame(self)
        self.main_frame.pack(pady=20, padx=20, fill="both", expand=True)

        self.password_label = ctk.CTkLabel(self.main_frame, text="Enter your password:")
        self.password_label.pack(pady=10)

        self.entry_frame = ctk.CTkFrame(self.main_frame)
        self.entry_frame.pack(pady=10)

        self.password_entry = ctk.CTkEntry(self.entry_frame, show="*", width=300)
        self.password_entry.pack(side="left", padx=5)

        self.show_password_var = ctk.BooleanVar(value=False)
        self.show_password_check = ctk.CTkCheckBox(self.entry_frame, text="Show Password",
                                                   variable=self.show_password_var,
                                                   command=self.toggle_password_visibility)
        self.show_password_check.pack(side="left", padx=5)

        self.check_button = ctk.CTkButton(self.main_frame, text="Check Strength", command=self.check_strength)
        self.check_button.pack(pady=10)

        self.results_frame = ctk.CTkFrame(self.main_frame)
        self.results_frame.pack(pady=10, fill="x")

        self.strength_label = ctk.CTkLabel(self.results_frame, text="", font=("Arial", 14, "bold"))
        self.strength_label.pack(pady=5, anchor="w")

        self.strength_meter = ctk.CTkProgressBar(self.results_frame, width=300)
        self.strength_meter.pack(pady=5)
        self.strength_meter.set(0)

        self.feedback_label = ctk.CTkLabel(self.results_frame, text="", justify="left", anchor="w", wraplength=500)
        self.feedback_label.pack(pady=5, fill="x")

        self.entropy_label = ctk.CTkLabel(self.results_frame, text="", anchor="w")
        self.entropy_label.pack(pady=5, anchor="w")

        self.crack_label = ctk.CTkLabel(self.results_frame, text="", justify="left", anchor="w", wraplength=500)
        self.crack_label.pack(pady=5, fill="x")

        self.suggest_button = ctk.CTkButton(self.main_frame, text="Suggest Strong Password",
                                            command=self.suggest_password)
        self.suggest_button.pack(pady=10)

        self.suggested_label = ctk.CTkLabel(self.main_frame, text="", wraplength=500, font=("Arial", 12))
        self.suggested_label.pack(pady=10)


        self.copy_button = ctk.CTkButton(self.main_frame, text="Copy to Clipboard", command=self.copy_to_clipboard)
        self.copy_button.pack(pady=10)
        self.copy_button.pack_forget()

        self.exit_button = ctk.CTkButton(self.main_frame, text="Exit", command=self.destroy, width=60, fg_color="red", hover_color="dark red")
        self.exit_button.pack(pady=10)


    def toggle_password_visibility(self):
        if self.show_password_var.get():
            self.password_entry.configure(show="")
        else:
            self.password_entry.configure(show="*")

    def check_strength(self):
        password = self.password_entry.get()
        if not password:
            self.strength_label.configure(text="No password entered", text_color="gray")
            self.strength_meter.set(0)
            self.strength_meter.configure(progress_color="gray")
            self.feedback_label.configure(text="")
            self.entropy_label.configure(text="")
            self.crack_label.configure(text="")
            return

        strength, feedback, entropy, crack_time = self.evaluate_strength(password)
        if strength == "Weak":
            self.strength_label.configure(text="Password Strength: Weak", text_color="red")
            self.strength_meter.set(0.33)
            self.strength_meter.configure(progress_color="red")
        elif strength == "Medium":
            self.strength_label.configure(text="Password Strength: Medium", text_color="yellow")
            self.strength_meter.set(0.66)
            self.strength_meter.configure(progress_color="yellow")
        else:
            self.strength_label.configure(text="Password Strength: Strong", text_color="green")
            self.strength_meter.set(1.0)
            self.strength_meter.configure(progress_color="green")

        if feedback:
            self.feedback_label.configure(text="Feedback:\n" + "\n".join(feedback))
        else:
            self.feedback_label.configure(text="Feedback: Great password!")

        self.entropy_label.configure(text=f"Estimated Entropy: {entropy:.2f} bits (higher is better)")
        self.crack_label.configure(text=f"Estimated Crack Time:\n{crack_time}\n\n\n(Note: This is an approximation assuming an offline attack with a powerful computer trying 1 billion guesses per second. Real times vary based on hashing method and attacker resources.)")

    def evaluate_strength(self, password):
        feedback = []
        if len(password) < 8:
            feedback.append("Password is too short. Use at least 8 characters.")
            return "Weak", feedback, 0.0, "Instant"

        has_lower = re.search(r"[a-z]", password) is not None
        has_upper = re.search(r"[A-Z]", password) is not None
        has_digit = re.search(r"[0-9]", password) is not None
        has_symbol = re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>/?]", password) is not None

        charset_size = 0
        if has_lower:
            charset_size += 26
        else:
            feedback.append("Add lowercase letters to increase strength.")
        if has_upper:
            charset_size += 26
        else:
            feedback.append("Add uppercase letters.")
        if has_digit:
            charset_size += 10
        else:
            feedback.append("Add digits.")
        if has_symbol:
            charset_size += 32
        else:
            feedback.append("Add special characters.")

        if len(password) < 12:
            feedback.append("Consider making it 12 characters or longer for better security.")

        score = sum([has_lower, has_upper, has_digit, has_symbol]) + (1 if len(password) >= 12 else 0)

        if score < 3:
            strength = "Weak"
        elif score < 5:
            strength = "Medium"
        else:
            strength = "Strong"

        entropy = len(password) * math.log2(charset_size) if charset_size > 0 else 0.0

        guesses_per_second = 1e9
        if entropy > 400:
            crack_seconds = float('inf')
        else:
            crack_seconds = (2 ** entropy) / guesses_per_second
        crack_time = self.format_crack_time(crack_seconds)

        return strength, feedback, entropy, crack_time

    def format_crack_time(self, seconds):
        if seconds == float('inf'):
            return "Centuries or more"
        if seconds < 1:
            return "Instant"
        elif seconds < 60:
            return f"{int(seconds)} seconds"
        elif seconds < 3600:
            return f"{int(seconds // 60)} minutes"
        elif seconds < 86400:
            return f"{int(seconds // 3600)} hours"
        elif seconds < 31536000:
            return f"{int(seconds // 86400)} days"
        elif seconds < 31536000 * 100:
            return f"{int(seconds // 31536000)} years"
        else:
            return "Centuries"

    def suggest_password(self):
        characters = string.ascii_letters + string.digits + string.punctuation
        secure_password = ''.join(secrets.choice(characters) for i in range(16))

        self.suggested_label.configure(text=f"Suggested: {secure_password}")
        self.exit_button.pack_forget()
        self.copy_button.pack(pady=10)
        self.exit_button.pack(pady=10)
        self._current_suggestion = secure_password

    def copy_to_clipboard(self):
        if hasattr(self, '_current_suggestion'):
            pyperclip.copy(self._current_suggestion)


if __name__ == "__main__":
    app = PasswordApp()
    app.mainloop()