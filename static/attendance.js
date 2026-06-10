const video = document.getElementById('video');
const canvas = document.getElementById('canvas');
const preview = document.getElementById('preview');
const startCamera = document.getElementById('startCamera');
const capturePhoto = document.getElementById('capturePhoto');
const getLocation = document.getElementById('getLocation');
const signInBtn = document.getElementById('signInBtn');
const signOutBtn = document.getElementById('signOutBtn');
const actionInput = document.getElementById('actionInput');
const cameraStatus = document.getElementById('cameraStatus');
const locationStatus = document.getElementById('locationStatus');
const photoData = document.getElementById('photo_data');
const latInput = document.getElementById('latitude');
const lngInput = document.getElementById('longitude');
const accInput = document.getElementById('accuracy');
const deviceTime = document.getElementById('device_time');
const securityStatus = document.getElementById('securityStatus');

let securityBlocked = false;
let cameraReady = false;
let photoReady = false;
let locationReady = false;
let geofenceBlocked = true;
let selectedAction = '';
let locationConfig = null;

function metersBetween(lat1, lon1, lat2, lon2) {
  const R = 6371000;
  const toRad = (v) => v * Math.PI / 180;
  const dLat = toRad(lat2 - lat1);
  const dLon = toRad(lon2 - lon1);
  const a = Math.sin(dLat/2) ** 2 + Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) * Math.sin(dLon/2) ** 2;
  return R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
}

async function loadLocationConfig() {
  try {
    const res = await fetch('/location-config', {cache:'no-store'});
    locationConfig = await res.json();
  } catch(e) {
    locationConfig = {
      center_lat: 24.2651997,
      center_lng: 55.7314160,
      radius_m: 250,
      max_gps_accuracy_m: 250,
      mode: 'circle'
    };
  }
}

function setAction(action) {
  selectedAction = action;
  actionInput.value = action;
}

function updateButtons(){
  deviceTime.value = 'SERVER_UAE_TIME_ONLY';
  const ready = photoReady && locationReady && !securityBlocked && !geofenceBlocked;
  if (signInBtn) signInBtn.disabled = !(ready && window.CAN_SIGN_IN);
  if (signOutBtn) signOutBtn.disabled = !(ready && window.CAN_SIGN_OUT);
}

async function checkSecurity(){
  if(!securityStatus){ return; }
  try{
    const res = await fetch('/security-status', {cache:'no-store'});
    const data = await res.json();
    if(data.blocked){
      securityBlocked = true;
      securityStatus.textContent = `Security: BLOCKED - ${data.reason}. Turn off VPN/proxy and use the normal local network.`;
      alert(`Blocked: ${data.reason}. Turn off VPN/proxy and try again.`);
    }else{
      securityBlocked = false;
      securityStatus.textContent = `Security: ${data.reason}${data.ip ? ' | IP: '+data.ip : ''}`;
    }
  }catch(e){
    securityBlocked = false;
    securityStatus.textContent = 'Security: IP/VPN check could not be completed now. Server will check again on submit.';
  }
  updateButtons();
}

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
  checkSecurity();
  updateButtons();
});

getLocation.addEventListener('click', async ()=>{
  if(!navigator.geolocation){
    locationStatus.textContent = 'Location is not supported on this device.';
    return;
  }
  await loadLocationConfig();
  locationStatus.textContent = 'Location: checking against saved allowed center...';
  navigator.geolocation.getCurrentPosition((pos)=>{
    const userLat = pos.coords.latitude;
    const userLng = pos.coords.longitude;
    const accuracy = pos.coords.accuracy;
    const centerLat = Number(locationConfig.center_lat);
    const centerLng = Number(locationConfig.center_lng);
    const radius = Number(locationConfig.radius_m);
    const maxAccuracy = Number(locationConfig.max_gps_accuracy_m);
    const distance = metersBetween(centerLat, centerLng, userLat, userLng);

    latInput.value = userLat;
    lngInput.value = userLng;
    accInput.value = accuracy;

    if (accuracy > maxAccuracy) {
      locationReady = false;
      geofenceBlocked = true;
      locationStatus.textContent = `Location: BLOCKED. GPS accuracy ${Math.round(accuracy)} m is weaker than allowed ${Math.round(maxAccuracy)} m.`;
      updateButtons();
      return;
    }

    if (distance > radius) {
      locationReady = false;
      geofenceBlocked = true;
      locationStatus.textContent = `Location: BLOCKED. You are ${Math.round(distance)} m from saved center (${centerLat.toFixed(7)}, ${centerLng.toFixed(7)}). Allowed radius is ${Math.round(radius)} m.`;
      updateButtons();
      return;
    }

    locationReady = true;
    geofenceBlocked = false;
    locationStatus.textContent = `Location: OK. You are ${Math.round(distance)} m from saved center (${centerLat.toFixed(7)}, ${centerLng.toFixed(7)}). GPS accuracy ${Math.round(accuracy)} m. Allowed radius ${Math.round(radius)} m.`;
    checkSecurity();
    updateButtons();
  },(err)=>{
    locationStatus.textContent = 'Location blocked or unavailable. Attendance cannot be submitted.';
  },{enableHighAccuracy:true, timeout:15000, maximumAge:0});
});

if (signInBtn) {
  signInBtn.addEventListener('click', () => setAction('IN'));
}
if (signOutBtn) {
  signOutBtn.addEventListener('click', () => setAction('OUT'));
}

document.getElementById('attendanceForm').addEventListener('submit',(e)=>{
  if(!photoReady || !locationReady){
    e.preventDefault();
    alert('Camera photo and valid location inside the saved allowed center are required.');
    return;
  }
  if(securityBlocked){
    e.preventDefault();
    alert('Attendance blocked because VPN/proxy/datacenter IP was detected.');
    return;
  }
  if(geofenceBlocked){
    e.preventDefault();
    alert('Attendance blocked because you are outside the saved allowed location or GPS accuracy is weak.');
    return;
  }
  if(!actionInput.value){
    e.preventDefault();
    alert('Please select Sign In or Sign Out.');
  }
});

loadLocationConfig();
checkSecurity();
updateButtons();
