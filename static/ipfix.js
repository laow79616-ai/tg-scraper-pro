(function(){
  function box(){ return document.getElementById("ip-pool-list") || document.getElementById("ip-saved-list"); }
  function numberCards(){
    var b=box(); if(!b) return;
    var cards=[].slice.call(b.children||[]);
    cards.forEach(function(el,i){
      var title=el.querySelector("b,strong,code,pre,.proxy") || el.firstElementChild;
      if(!title) return;
      var txt=(title.textContent||"").replace(/^\s*\d+\.\s*/,"");
      title.textContent=(i+1)+". "+txt;
    });
  }
  async function save(){
    var ta=document.getElementById("ip-new") || document.getElementById("ip-input") || document.querySelector("textarea");
    var text=ta?ta.value:"";
    var r=await fetch("/api/ip-pool",{
      method:"POST",
      headers:{"Content-Type":"application/json"},
      body:JSON.stringify({text:text,lines:text.split("\n")})
    });
    var d=await r.json();
    alert("保存结果 added="+(d.added||0)+" count="+(d.count||0));
    location.reload();
  }
  function hook(){
    var btn=document.getElementById("btn-save-ip");
    if(!btn) return;
    var n=btn.cloneNode(true);
    n.id="btn-save-ip";
    n.onclick=function(e){ e.preventDefault(); e.stopPropagation(); save(); return false; };
    btn.parentNode.replaceChild(n,btn);
    numberCards();
  }
  document.addEventListener("DOMContentLoaded", hook);
  setTimeout(hook,500);
  setInterval(numberCards,1000);
})();
