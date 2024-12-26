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
      <FileSharing />
    </div>
  );
};

export default FileUpload;
