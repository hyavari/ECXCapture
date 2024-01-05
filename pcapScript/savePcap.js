const AWS = require("aws-sdk");
const s3 = new AWS.S3();
const fs = require("fs");

const fileNameWithPath = process.argv[2] || "ecs-pcap.pcap"; // as the default
const s3Bucket = process.argv[3] || "bucket-pcaps"; // Use "nginx-pcaps-prod" as the default

// Use the provided file name
try {
  const data = fs.readFileSync(fileNameWithPath);
  const fileName = fileNameWithPath.includes('/') ? fileNameWithPath.split('/').pop() : fileNameWithPath;

  let params = { Bucket: s3Bucket, Key: fileName, Body: data };
  s3.putObject(params, function (err, data) {
    if (err) console.log(err);
    else
      console.log(
        `Successfully saved object to bucket with key: ${fileName}`
      );
  });
} catch (err) {
  console.error(err);
}