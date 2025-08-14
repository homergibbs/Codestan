import json
import os

# Paths (based on your current setup)
input_json_path = "/Users/floranlechauve/Desktop/AI/Doc Wild Code School/Codestan/Cerveau Codestan/Json/set_ok.json"  # Original JSON
output_json_path = "/Users/floranlechauve/Desktop/AI/Doc Wild Code School/Codestan/Cerveau Codestan/codequizz/set_ok_cleaned.json"  # Cleaned JSON

def clean_image_paths(json_path, output_path):
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    for question in data:
        img_path = question.get("image_path")
        if img_path:
            filename = os.path.basename(img_path)  # Extract the filename from the path
            question["image_path"] = f"/static/images/{filename}"  # Update to the correct path format

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    print(f"✅ Cleaned JSON saved as: {output_path}")

# Run the cleaning process
clean_image_paths(input_json_path, output_json_path)
