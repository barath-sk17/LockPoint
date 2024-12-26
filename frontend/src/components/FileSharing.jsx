import React, { useState, useEffect, useRef } from "react";
import axiosInstance from "../api/axios";
import { saveAs } from "file-saver";
import { Base64 } from "js-base64";

const FileSharing = () => {
  const [currentTab, setCurrentTab] = useState("my_files");
  const [files, setFiles] = useState([]);
  const [fileToShare, setFileToShare] = useState(null);
  const [emails, setEmails] = useState([""]); // Start with one email input
  const [pagination, setPagination] = useState({ page: 1, totalPages: 2 });
  const [threeDots,setThreeDots] = useState(false);
  const [selectedFile, setSelectedFile] = useState(null);
  const [selectedACLFile,setSelectedACLFile] = useState(null);
  const [sharingList, setSharingList] = useState(selectedACLFile?.sharing || []);

  //const [showDeleteConfirmation, setShowDeleteConfirmation] = useState(false); 
  const dropdownRef = useRef(null);


  useEffect(() => {
    // Fetch files based on the tab (my_files or shared)
    const fetchFiles = async () => {
      try {
        const response = await axiosInstance.get(`/api/files/${currentTab}`, {
          headers: {
            Authorization: `Bearer ${localStorage.getItem("token")}`, // JWT token for authentication
          },
        });
        setFiles(response.data.files);
        console.log("Files",files);
        setPagination(response.data.pagination || { page: 1, totalPages: 1 });
      } catch (error) {
        console.error("Error fetching files", error);
      }
    };

    fetchFiles();
  }, [currentTab, pagination.page]);

  // Close dropdown when clicking outside of it
  useEffect(() => {
    const handleClickOutside = (event) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target)) {
        setThreeDots(false);
      }
    };
    document.addEventListener("click", handleClickOutside);
    return () => {
      document.removeEventListener("click", handleClickOutside);
    };
  }, []);


  // Utility function to format file size
 const formatFileSize = (sizeInBytes) => {
    if (sizeInBytes < 1024) {
      return `${sizeInBytes} B`; // Bytes
    } else if (sizeInBytes < 1024 * 1024) {
      return `${(sizeInBytes / 1024).toFixed(2)} KB`; // Kilobytes
    } else if (sizeInBytes < 1024 * 1024 * 1024) {
      return `${(sizeInBytes / (1024 * 1024)).toFixed(2)} MB`; // Megabytes
    } else {
      return `${(sizeInBytes / (1024 * 1024 * 1024)).toFixed(2)} GB`; // Gigabytes
    }
  };
  
  const handleDownload = async (fileKey,fileName) => {
    // try {
    //   const response = await axiosInstance.get(`/api/files/download/${file._id}`);
    //   const link = document.createElement("a");
    //   link.href = response.data.url;
    //   link.download = file.file_name;
    //   link.click();
    // } catch (error) {
    //   console.error("Error downloading file", error);
    // }
    // Download file

    try {
      const token = localStorage.getItem("token");
      const response = await axiosInstance.get(`/api/files/download/${fileKey}`, {
        headers: { Authorization: `Bearer ${token}` },
      });

      // Decode base64 content
      const fileContent = Base64.toUint8Array(response.data.content);
      const blob = new Blob([fileContent], { type: response.data.file_type });

      // Use file-saver to download the file
      saveAs(blob, fileName);
    } catch (error) {
      console.error("Error downloading file:", error);
      alert("Failed to download file.");
    }
  };

  

  const handleDelete = async (file) => {
    try {
      const token = localStorage.getItem("token");

      await axiosInstance.delete(`/api/files/delete/${file._id}`,{headers: { Authorization: `Bearer ${token}` },});
      alert("File deleted successfully");
      setFiles(files.filter((f) => f._id !== file._id));
    } catch (error) {
      alert(error.response.data.error)
      console.error("Error deleting file", error);
    }
  };



  const handleEmailChange = (e, index) => {
    const newEmails = [...emails];
    newEmails[index] = e.target.value;
    setEmails(newEmails);
  };

  const handleAddEmail = () => {
    setEmails([...emails, ""]); // Add a new email field
  };

  const handleRemoveEmail = (index) => {
    const newEmails = emails.filter((_, i) => i !== index);
    setEmails(newEmails);
  };

  const handleShareSubmit = async () => {
    try {
      for (const email of emails) {
        if (!email) continue; // Skip empty email fields
        if (email === fileToShare.owner) {
          alert("Sharing with your own email address is not allowed. Please use another email address.");
          return; // Exit early
        }

        console.log("File ID", fileToShare._id, " Email ", email);
        await axiosInstance.post(
          "/api/share-file",
          {
            file_id: fileToShare._id,
            email,
          },
          {
            headers: {
              Authorization: `Bearer ${localStorage.getItem("token")}`, // JWT token for authentication
            },
          }
        );
      }
      alert("File shared successfully!");
      setEmails([""]); // Clear email inputs
      setFileToShare(null); // Close sharing dialog
    } catch (error) {
      console.error("Error sharing file", error);
      alert("Error sharing file.");
    }
  };

  const handleRevokeEmail = (index) => {
    const newSharingList = [...sharingList];
    newSharingList.splice(index, 1);
    setSharingList(newSharingList);
  };

  const handleRevokeSubmit = async () => {
    try {
      const response = await axiosInstance.post('/api/files/revoke-access', {
        file_id: selectedACLFile._id,
        email: sharingList,  // Passing all emails to backend
      }, {
        headers: {
          Authorization: `Bearer ${localStorage.getItem("token")}`, // JWT token for authentication
        },
      });
      alert(response.data.message); // Optionally show success message
      setSharingList(null);
      setSelectedACLFile(null); // Close modal after success
    } catch (error) {
      alert('Error revoking access: ' + error.response.data.error); // Handle error
    } finally {
    }
  };


  return (
    <div className="flex w-full">
      {/* Left Section: Tabs */}
      <div className="w-1/4 p-4 bg-gray-200 rounded-lg shadow">
        <button
          onClick={() => setCurrentTab("my_files")}
          className={`w-full rounded-lg text-center py-2 mb-2 ${currentTab === "my_files" ? "bg-blue-500 text-white" : "bg-gray-300"}`}
        >
          My Files
        </button>
        <button
          onClick={() => setCurrentTab("shared")}
          className={`w-full rounded-lg text-center py-2 mb-2 ${currentTab === "shared" ? "bg-blue-500 text-white" : "bg-gray-300"}`}
        >
          Shared Files
        </button>
      </div>

      {/* Right Section: File Table */}
      <div className="w-3/4 p-4">
        <h2 className="text-xl font-semibold mb-4">{currentTab === "my_files" ? "My Files" : "Shared Files"}</h2>

        <table className="w-full table-auto border-collapse">
          <thead>
            <tr>
              <th className="border-b px-4 py-2">File Name</th>
              <th className="border-b px-4 py-2">File Type</th>
              <th className="border-b px-4 py-2">File Size</th>
              <th className="border-b px-4 py-2">Actions</th>
            </tr>
          </thead>
          <tbody>
            {files.map((file) => (
              <tr key={file._id}>
                <td className="border-b px-4 py-2 text-center">
                {file.file_name.split('.').slice(0, -1).join('.')}
                </td>
                <td className="border-b px-4 py-2 text-center">
                {file.file_name.split('.').pop()}
                </td>
                <td className="border-b px-4 py-2 text-center">{formatFileSize(file.file_size)} </td>
                <td className="relative border-b px-4 py-2 text-center">
                  <button onClick={() => { setThreeDots(!threeDots);
                    setSelectedFile(file); }} className="text-blue-500">...</button>
                {threeDots && selectedFile._id===file._id && (
                  <div className="absolute right-0 top-[100%] z-10 mt-1 bg-white border rounded shadow-lg">
                    <ul>
                      <li>
                        <button onClick={() => handleDownload(file.file_key,file.file_name)} className="rounded w-full text-left block px-4 py-2 hover:bg-blue-500">
                          Download
                        </button>
                      </li>
                      {currentTab==='my_files' &&
                      <div>
                      <li>
                        <button
                          onClick={() => {
                            setFileToShare(file);
                            setThreeDots(false);
                          }}
                          className="block px-4 py-2 w-full hover:bg-blue-500 text-left rounded"
                        >
                          Share with
                        </button>
                      </li>
                      <li>
                        <button className="block px-4 w-full py-2 hover:bg-blue-500 text-left rounded" onClick={() =>{setSelectedACLFile(file);setSharingList(file.sharing)}}>See ACL</button>
                      </li>
                      <li>
                        <button
                          onClick={() => handleDelete(file)}
                          className="block px-4 py-2 w-full text-red-500 hover:bg-blue-500 text-left rounded"
                        >
                          Delete
                        </button>
                      </li>
                      </div>
                    }
                    </ul>
                  </div>
                )}

                </td>
              </tr>
            ))}
          </tbody>
        </table>

        {/* Pagination */}
        <div className="mt-4 flex justify-between">
          <button
            onClick={() => setPagination((prev) => ({ ...prev, page: Math.max(prev.page - 1, 1) }))}
            disabled={pagination.page === 1}
            className="bg-blue-500 text-white px-4 py-2 rounded disabled:opacity-50"
          >
            Prev
          </button>
          <span>{pagination.page} / {pagination.totalPages}</span>
          <button
            onClick={() => setPagination((prev) => ({ ...prev, page: Math.min(prev.page + 1, pagination.totalPages) }))}
            disabled={pagination.page === pagination.totalPages}
            className="bg-blue-500 text-white px-4 py-2 rounded disabled:opacity-50"
          >
            Next
          </button>
        </div>
      </div>

      {selectedACLFile && (
        <div className="fixed inset-0 flex items-center justify-center bg-black bg-opacity-50">
          <div className="bg-white p-6 rounded shadow-md w-1/3">
            <h3 className="text-lg font-semibold mb-4">The ACL List</h3>
            <p className="mb-2">File Name {selectedACLFile.file_name}</p>

            {sharingList.map((email, index) => (
            <div key={index} className="mb-4 flex justify-between p-2 rounded shadow-sm">
              <p>{email}</p>
              <button
                onClick={() => handleRevokeEmail(index)}
                className="text-red-500 ml-2"
              >
                Revoke
              </button>
            </div>
          ))}

            <button
              onClick={handleRevokeSubmit}
              className="ml-2 bg-blue-500 text-white px-4 py-2 rounded"
            >
              Submit
            </button>
            <button
              onClick={() => setSelectedACLFile(null)}
              className="ml-2 bg-gray-500 text-white px-4 py-2 rounded"
            >
              Cancel
            </button>
          </div>
        </div>
      )}


      {/* Share File Dialog */}
      {fileToShare && (
        <div className="fixed inset-0 flex items-center justify-center bg-black bg-opacity-50">
          <div className="bg-white p-6 rounded shadow-lg w-1/3">
            <h3 className="text-lg font-semibold mb-4">Share File</h3>
            <p className="mb-2">Enter the email(s) to share the file with:</p>

            {emails.map((email, index) => (
              <div key={index} className="mb-4">
                <input
                  type="email"
                  value={email}
                  onChange={(e) => handleEmailChange(e, index)}
                  className="border border-gray-300 p-2 w-full mb-2"
                  placeholder="Email address"
                />
                <button
                  onClick={() => handleRemoveEmail(index)}
                  className="text-red-500 ml-2"
                >
                  Remove
                </button>
              </div>
            ))}

            <button
              onClick={handleAddEmail}
              className="bg-blue-500 text-white px-4 py-2 rounded mb-4"
            >
              Add More Emails
            </button>

            <button
              onClick={handleShareSubmit}
              className="ml-2 bg-blue-500 text-white px-4 py-2 rounded"
            >
              Share
            </button>
            <button
              onClick={() => setFileToShare(null)}
              className="ml-2 bg-gray-500 text-white px-4 py-2 rounded"
            >
              Cancel
            </button>
          </div>
        </div>
      )}
    </div>
  );
};

export default FileSharing;
