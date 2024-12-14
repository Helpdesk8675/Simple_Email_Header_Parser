import tkinter as tk
from tkinter import filedialog, scrolledtext
import email
from email.header import decode_header
import os

class EmailHeaderDecoderGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Email Header Decoder")
        self.root.geometry("800x600")

        # Create GUI elements
        self.create_widgets()

    def create_widgets(self):
        # Create buttons frame
        button_frame = tk.Frame(self.root)
        button_frame.pack(pady=10)

        # Add Open File button
        self.open_button = tk.Button(button_frame, text="Open Header File", command=self.open_file)
        self.open_button.pack(side=tk.LEFT, padx=5)

        # Add Clear button
        self.clear_button = tk.Button(button_frame, text="Clear", command=self.clear_text)
        self.clear_button.pack(side=tk.LEFT, padx=5)

        # Create text area for displaying decoded headers
        self.text_area = scrolledtext.ScrolledText(self.root, wrap=tk.WORD, width=80, height=30)
        self.text_area.pack(padx=10, pady=10, expand=True, fill='both')

    def decode_header_value(self, header_value):
        decoded_parts = []
        for part, charset in decode_header(header_value):
            if isinstance(part, bytes):
                try:
                    decoded_part = part.decode(charset if charset else 'utf-8', errors='replace')
                except:
                    decoded_part = part.decode('utf-8', errors='replace')
            else:
                decoded_part = part
            decoded_parts.append(decoded_part)
        return ' '.join(decoded_parts)

    def parse_headers(self, content):
        # Create an email message object
        msg = email.message_from_string(content)
        
        decoded_headers = []
        for header, value in msg.items():
            decoded_value = self.decode_header_value(value)
            decoded_headers.append(f"{header}: {decoded_value}")
        
        return '\n'.join(decoded_headers)

    def open_file(self):
        file_path = filedialog.askopenfilename(
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if file_path:
            try:
                with open(file_path, 'r', encoding='utf-8') as file:
                    content = file.read()
                
                # Parse and decode headers
                decoded_content = self.parse_headers(content)
                
                # Clear existing content and insert decoded headers
                self.text_area.delete(1.0, tk.END)
                self.text_area.insert(tk.END, decoded_content)
                
            except Exception as e:
                self.text_area.delete(1.0, tk.END)
                self.text_area.insert(tk.END, f"Error reading file: {str(e)}")

    def clear_text(self):
        self.text_area.delete(1.0, tk.END)

def main():
    root = tk.Tk()
    app = EmailHeaderDecoderGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
