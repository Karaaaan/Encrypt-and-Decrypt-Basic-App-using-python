from tkinter import *

# Set up main window
window = Tk()
window.title("PASSWORD ENCRYPTOR")
window.geometry("800x600")

# Title label
label = Label(window, text="ENCRYPT || DECRYPT", font=("Arial", 25))
label.pack()

# Create frames for encryption and decryption
encrypt_frame = Frame(window)
decrypt_frame = Frame(window)

def clear_frames():
    """Clear both frames before switching to avoid overlapping widgets."""
    for widget in encrypt_frame.winfo_children():
        widget.destroy()  # Destroy all widgets in encrypt_frame
    for widget in decrypt_frame.winfo_children():
        widget.destroy()  # Destroy all widgets in decrypt_frame
    encrypt_frame.pack_forget()  # Forget the pack layout of encrypt_frame
    decrypt_frame.pack_forget()  # Forget the pack layout of decrypt_frame

def encrypt():
    """Switch to encryption frame."""
    clear_frames()  # Clear existing frames
    encrypt_frame.pack()  # Display encryption frame
    label1 = Label(encrypt_frame, text="YOU DECIDED TO ENCRYPT", font=("Arial", 16))
    label1.pack()  # Pack label into encryption frame
    message_entry = Entry(encrypt_frame)
    message_entry.pack()  # Pack entry widget into encryption frame

    def confirmE():
        """Handle encryption process."""
        message = message_entry.get()  # Get text from entry widget
        encrypted_message = "".join([chr(ord(letter) + 3) for letter in message])  # Shift ASCII by 3
        label2 = Label(encrypt_frame, text="ENCRYPTED MESSAGE: " + encrypted_message, font=("Arial", 14))
        label2.pack()  # Pack encrypted message label into encryption frame

    button1 = Button(encrypt_frame, text="CONFIRM", command=confirmE)
    button1.pack()  # Pack confirm button into encryption frame

def decrypt():
    """Switch to decryption frame."""
    clear_frames()  # Clear existing frames
    decrypt_frame.pack()  # Display decryption frame
    label1 = Label(decrypt_frame, text="YOU DECIDED TO DECRYPT", font=("Arial", 16))
    label1.pack()  # Pack label into decryption frame
    message_entry = Entry(decrypt_frame)
    message_entry.pack()  # Pack entry widget into decryption frame

    def confirmD():
        """Handle decryption process."""
        message = message_entry.get()  # Get text from entry widget
        decrypted_message = "".join([chr(ord(letter) - 3) for letter in message])  # Shift ASCII by -3
        label2 = Label(decrypt_frame, text="DECRYPTED MESSAGE: " + decrypted_message, font=("Arial", 14))
        label2.pack()  # Pack decrypted message label into decryption frame

    button1 = Button(decrypt_frame, text="CONFIRM", command=confirmD)
    button1.pack()  # Pack confirm button into decryption frame

# Main Encrypt and Decrypt buttons
button1 = Button(window, text="Encrypt", command=encrypt)
button1.pack()  # Pack encrypt button into main window
button2 = Button(window, text="Decrypt", command=decrypt)
button2.pack()  # Pack decrypt button into main window

window.mainloop()
