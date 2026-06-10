const video = document.getElementById('video');
const canvas = document.getElementById('canvas');
const preview = document.getElementById('preview');
const startCamera = document.getElementById('startCamera');
const capturePhoto = document.getElementById('capturePhoto');
const getLocation = document.getElementById('getLocation');
const submitBtn = document.getElementById('submitBtn');
const cameraStatus = document.getElementById('cameraStatus');
const locationStatus = document.getElementById('locationStatus');
const photoData = document.getElementById('photo_data');
const latInput = document.getElementById('latitude');
const lngInput = document.getElementById('longitude');
const accInput = document.getElementById('accuracy');
const deviceTime = document.getElementById('device_time');
let cameraReady = false;
let photoReady = false;
let locationReady = false;
function updateButton(){
  deviceTime.value = new Date().toLocaleString();
  submitBtn.disabled = !(photoReady && locationReady);
}
setInterval(()=>{ deviceTime.value = new Date().toLocaleString(); },1000);
startCamera.addEventListener('click', async ()=>{
  try{
    const stream = await navigator.mediaDevices.getUserMedia({video:{facingMode:'user'}, audio:false});
    video.srcObject = stream;
    cameraReady = true;
    capturePhoto.disabled = false;
    cameraStatus.textContent = 'Camera: ready. Take a photo before submitting.';
  }catch(e){
    cameraStatus.textContent = 'Camera blocked or unavailable. Attendance cannot be submitted.';
  }
});
capturePhoto.addEventListener('click', ()=>{
  if(!cameraReady){ return; }
  canvas.width = video.videoWidth || 640;
  canvas.height = video.videoHeight || 480;
  const ctx = canvas.getContext('2d');
  ctx.drawImage(video,0,0,canvas.width,canvas.height);
  const data = canvas.toDataURL('image/jpeg',0.86);
  photoData.value = data;
  preview.src = data;
  preview.style.display = 'block';
  photoReady = true;
  cameraStatus.textContent = 'Camera: required photo captured.';
  updateButton();
});
getLocation.addEventListener('click', ()=>{
  if(!navigator.geolocation){
    locationStatus.textContent = 'Location is not supported on this device.';
    return;
  }
  locationStatus.textContent = 'Location: checking...';
  navigator.geolocation.getCurrentPosition((pos)=>{
    latInput.value = pos.coords.latitude;
    lngInput.value = pos.coords.longitude;
    accInput.value = pos.coords.accuracy;
    locationReady = true;
    locationStatus.textContent = `Location: ready (${pos.coords.latitude.toFixed(6)}, ${pos.coords.longitude.toFixed(6)}), accuracy ${Math.round(pos.coords.accuracy)} m`;
    updateButton();
  },(err)=>{
    locationStatus.textContent = 'Location blocked or unavailable. Attendance cannot be submitted.';
  },{enableHighAccuracy:true, timeout:15000, maximumAge:0});
});
document.getElementById('attendanceForm').addEventListener('submit',(e)=>{
  updateButton();
  if(!photoReady || !locationReady){
    e.preventDefault();
    alert('Camera photo and location are both required.');
  }
});
updateButton();
