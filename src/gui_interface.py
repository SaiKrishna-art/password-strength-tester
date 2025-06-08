import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from password_analyzer import PasswordAnalyzer
from password_generator import generate_strong_password


class PasswordAnalyzerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Strength Analyzer")
        self.root.geometry("600x400")
        self.root.resizable(True, True)

        # Apply a modern theme
        self.style = ttk.Style()
        self.style.theme_use("clam")

        self.create_widgets()

    def create_widgets(self):
        # Create main frame
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Title
        title = ttk.Label(
            main_frame,
            text="🔒 Password Strength Analyzer",
            font=("Arial", 16, "bold"),
            foreground="#2c3e50"
        )
        title.grid(row=0, column=0, columnspan=2, pady=(0, 20))

        # Password input
        input_frame = ttk.Frame(main_frame)
        input_frame.grid(row=1, column=0, columnspan=2, sticky=tk.EW, pady=(0, 15))

        ttk.Label(input_frame, text="Enter Password:").pack(side=tk.LEFT, padx=(0, 5))
        self.password_entry = ttk.Entry(input_frame, width=30, show="•")
        self.password_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))

        show_btn = ttk.Button(input_frame, text="👁️", width=3, command=self.toggle_visibility)
        show_btn.pack(side=tk.LEFT)
        self.show_password = False

        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=2, column=0, columnspan=2, pady=(0, 20))

        ttk.Button(
            button_frame,
            text="Analyze Password",
            command=self.analyze_password,
            style="Accent.TButton"
        ).pack(side=tk.LEFT, padx=5)

        ttk.Button(
            button_frame,
            text="Generate Password",
            command=self.generate_password
        ).pack(side=tk.LEFT, padx=5)

        ttk.Button(
            button_frame,
            text="Clear",
            command=self.clear_results
        ).pack(side=tk.LEFT, padx=5)

        # Results display
        results_frame = ttk.LabelFrame(main_frame, text="Analysis Results", padding=10)
        results_frame.grid(row=3, column=0, columnspan=2, sticky=tk.NSEW)

        self.result_text = scrolledtext.ScrolledText(
            results_frame,
            width=70,
            height=8,
            state=tk.DISABLED,
            font=("Consolas", 10)
        )
        self.result_text.pack(fill=tk.BOTH, expand=True)

        # Strength meter
        strength_frame = ttk.Frame(main_frame)
        strength_frame.grid(row=4, column=0, columnspan=2, sticky=tk.EW, pady=(15, 0))

        ttk.Label(strength_frame, text="Strength Meter:").pack(side=tk.LEFT)

        self.strength_meter = ttk.Progressbar(
            strength_frame,
            length=400,
            mode="determinate"
        )
        self.strength_meter.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(5, 0))

        self.strength_label = ttk.Label(strength_frame, text="0%", width=5)
        self.strength_label.pack(side=tk.LEFT, padx=(5, 0))

        # Status bar
        self.status_var = tk.StringVar(value="Ready")
        status_bar = ttk.Label(
            self.root,
            textvariable=self.status_var,
            relief=tk.SUNKEN,
            anchor=tk.W,
            padding=5
        )
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)

        # Configure grid weights
        main_frame.columnconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(3, weight=1)

        # Create custom button style
        self.style.configure("Accent.TButton", font=("Arial", 10, "bold"), foreground="white", background="#3498db")

        # Bind Enter key to analyze
        self.root.bind("<Return>", lambda e: self.analyze_password())

    def toggle_visibility(self):
        """Toggle password visibility"""
        self.show_password = not self.show_password
        show_char = "" if self.show_password else "•"
        self.password_entry.config(show=show_char)

    def analyze_password(self):
        """Analyze the entered password"""
        password = self.password_entry.get()
        if not password:
            messagebox.showwarning("Input Error", "Please enter a password")
            return

        self.status_var.set("Analyzing password...")
        self.root.update_idletasks()  # Update UI immediately

        try:
            analyzer = PasswordAnalyzer(password)
            result = analyzer.analyze()

            # Format results
            output = f"Password: {result['masked_password']}\n"
            output += f"Entropy: {result['entropy']} bits\n"
            output += f"Breach Occurrences: {result['breach_count']}\n"
            output += f"Strength Rating: {result['strength'].upper()}\n"
            output += f"Recommendation: {result['recommendation']}"

            # Update UI
            self.result_text.config(state=tk.NORMAL)
            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, output)
            self.result_text.config(state=tk.DISABLED)

            # Update strength meter
            if 'strength_score' in result:
                strength_value = result['strength_score']
            else:
                # Estimate strength if not provided
                strength_value = min(100, max(0, result['entropy'] * 1.5))

            self.strength_meter["value"] = strength_value
            self.strength_label.config(text=f"{int(strength_value)}%")

            # Color coding for strength
            if strength_value < 30:
                self.style.configure("Horizontal.TProgressbar", background="#e74c3c")
            elif strength_value < 70:
                self.style.configure("Horizontal.TProgressbar", background="#f39c12")
            else:
                self.style.configure("Horizontal.TProgressbar", background="#2ecc71")

            self.status_var.set("Analysis complete")

        except Exception as e:
            self.status_var.set("Error during analysis")
            messagebox.showerror("Analysis Error", f"An error occurred: {str(e)}")

    def generate_password(self):
        """Generate a strong password"""
        new_pass = generate_strong_password()
        self.password_entry.delete(0, tk.END)
        self.password_entry.insert(0, new_pass)
        self.status_var.set("Generated a new password")

    def clear_results(self):
        """Clear all inputs and results"""
        self.password_entry.delete(0, tk.END)
        self.result_text.config(state=tk.NORMAL)
        self.result_text.delete(1.0, tk.END)
        self.result_text.config(state=tk.DISABLED)
        self.strength_meter["value"] = 0
        self.strength_label.config(text="0%")
        self.status_var.set("Ready")
        self.style.configure("Horizontal.TProgressbar", background="#3498db")


if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordAnalyzerApp(root)
    root.mainloop()