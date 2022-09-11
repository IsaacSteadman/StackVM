function OutputCPP_BC_Enum(Name) {
  const cells2D = window.zz.cells2D;
  let Rtn = "enum " + Name + " {\n";
  for (let c = 0; c < cells2D.h; ++c) {
    Rtn +=
      "BC_" +
      cells2D.get(6, c).innerText +
      " = " +
      Number(cells2D.get(7, c).innerText) +
      ",\n";
  }
  Rtn += "};";
  return Rtn;
}
function OutputPython_BC_Enum(Name) {
  const cells2D = window.zz.cells2D;
  let Tab = "";
  let Rtn = "";
  if (Name != null) {
    Rtn += "class " + Name + ":\n";
    Tab = "    ";
  }
  for (let c = 0; c < cells2D.h; ++c) {
    Rtn +=
      Tab +
      "BC_" +
      cells2D.get(6, c).innerText +
      " = " +
      Number(cells2D.get(7, c).innerText) +
      "\n";
  }
  return Rtn;
}
function OutputJSON_BC_Enum() {
  const cells2D = window.zz.cells2D;
  let Rtn = {};
  for (let c = 0; c < cells2D.h; ++c) {
    Rtn[cells2D.get(6, c).innerText] = Number(cells2D.get(7, c).innerText);
  }
  return JSON.stringify(Rtn);
}
