import cv2
import pytesseract

# Set the path to the Tesseract executable if needed
# pytesseract.pytesseract.tesseract_cmd = r'/path/to/tesseract'

video_path = 'flag.avi'  # Replace with your video file path
output_file = 'output.txt'  # Replace with the desired output file path

# Open the video file
cap = cv2.VideoCapture(video_path)

# Create a file to save the extracted text
output_text_file = open(output_file, 'w')

while cap.isOpened():
    ret, frame = cap.read()
    if not ret:
        break

    # Convert frame to grayscale
    gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)

    # Perform text detection on the frame
    text = pytesseract.image_to_string(gray)

    # Save the extracted text to the file
    output_text_file.write(text)
    output_text_file.write('\n')

    # Display the text on the frame (optional)
    cv2.putText(frame, text, (10, 50), cv2.FONT_HERSHEY_SIMPLEX, 1, (0, 255, 0), 2)
    cv2.imshow('Video', frame)

    if cv2.waitKey(1) & 0xFF == ord('q'):
        break

cap.release()
cv2.destroyAllWindows()

# Close the output file
output_text_file.close()
