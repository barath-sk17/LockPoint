import React, { useState } from "react";
import { useDropzone } from "react-dropzone";
import axiosInstance from "../api/axios";
import FileSharing from "./FileSharing";
import Navbar from "./Navbar";

const FileUpload = () => {
  const [files, setFiles] = useState([]);
  const [uploading, setUploading] = useState(false);
  const [uploadError, setUploadError] = useState("");

  const { getRootProps, getInputProps } = useDropzone({
    accept: ".jpg,.jpeg,.png,.pdf,.docx,.txt", // Allowed file types
    onDrop: (acceptedFiles) => {
      setFiles(acceptedFiles); // Store selected files in state
      setUploadError(""); // Reset error if any
    },
  });

  const handleSubmit = async () => {
    console.log("Files",files);
    if (files.length === 0) {
      setUploadError("Please select at least one file to upload.");
      return;
    }
    setUploading(true);
    setUploadError("");

    const formData = new FormData();
    files.forEach((file) => {
      formData.append("files", file); // Append each file to form data
    });
    console.log("Form Data",formData);
    try {
      const response = await axiosInstance.post(
        "/api/upload-file", // Flask backend endpoint
        formData,
        {
          headers: {
            "Content-Type": "multipart/form-data",
            Authorization: `Bearer ${localStorage.getItem("token")}`, // JWT token for authentication
          },
        }
      );
      alert("Files uploaded successfully!");
    } catch (error) {
      setUploadError("Error uploading files. Please try again.");
      console.error("File upload error:", error);
    } finally {
      setUploading(false);
    }
  };

  return (
    <div className="p-6 w-full ">
       <Navbar />
       <br/>
       <div className="w-[50%] mx-auto mb-3">
        <div
            {...getRootProps()}
            className="border-4 border-dashed border-gray-400 p-8 cursor-pointer hover:bg-gray-50"
        >
            <input {...getInputProps()} />
            <p className="text-center text-gray-600">Drag & drop files here, or click to select files</p>
        </div>

        <div className="mt-4">
            <h3 className="text-lg font-semibold">Selected Files:</h3>
            <ul className="list-disc pl-5">
            {files.map((file, index) => (
                <li key={index} className="text-gray-700">{file.name}</li>
            ))}
            </ul>
        </div>

        {uploadError && <p className="text-red-500 mt-2">{uploadError}</p>}

        <button
            onClick={handleSubmit}
            disabled={uploading}
            className={`mt-4 w-full bg-blue-500 text-white p-3 rounded-md hover:bg-blue-600 ${
            uploading ? "opacity-50 cursor-not-allowed" : ""
            }`}
        >
            {uploading ? "Uploading..." : "Upload Files"}
        </button>
      </div>
    </div>
  );
};

export default FileUpload;
