{
  class TwoDimArray {
    constructor(w, h) {
      this.data = [];
      this.w = w;
      this.h = h;
      let Len = w * h;
      this.data.length = Len;
      for (let c = 0; c < Len; ++c) {
        this.data[c] = null;
      }
    }
    appendColumn(column) {
      if (column.length !== this.h) {
        throw new Error("column length must equal height");
      }
      let newData = [];
      newData.length = this.data.length + this.h;
      let newW = this.w + 1;
      for (let y = 0; y < this.h; ++y) {
        let off0 = y * this.w;
        let off1 = y * newW;
        for (let x = 0; x < this.w; ++x) {
          newData[off1 + x] = this.data[off0 + x];
        }
        newData[off1 + this.w] = column[y];
      }
      this.w = newW;
      this.data = newData;
    }
    index(x, y) {
      if (x >= this.w) {
        throw new Error("x must be less than width");
      }
      if (y >= this.h) {
        throw new Error("y must be less than height");
      }
      return y * this.w + x;
    }
    get(x, y) {
      return this.data[this.index(x, y)];
    }
    set(x, y, v) {
      return (this.data[this.index(x, y)] = v);
    }
  }
  function nullArray(sz) {
    let rtn = [];
    rtn.length = sz;
    for (let c = 0; c < sz; ++c) {
      rtn[c] = null;
    }
    return rtn;
  }
  class TableHelper {
    constructor(tblDom) {
      let tbodies = tblDom.getElementsByTagName("tbody");
      if (tbodies.length !== 1) {
        throw new Error("Expected exactly 1 <tbody>");
      }
      this.tbody = tbodies[0];
      this.rows = this.tbody.getElementsByTagName("tr");
      this.cells2D = new TwoDimArray(0, this.rows.length);
      for (let c = 0; c < this.rows.length; ++c) {
        let row = this.rows[c];
        let posNull = 0;
        while (
          posNull < this.cells2D.w &&
          this.cells2D.get(posNull, c) != null
        ) {
          ++posNull;
        }
        for (let c0 = 0; c0 < row.cells.length; ++c0) {
          let cell = row.cells[c0];
          while (posNull + cell.colSpan > this.cells2D.w) {
            this.cells2D.appendColumn(nullArray(this.cells2D.h));
          }
          for (let x = 0; x < cell.colSpan; ++x) {
            let offX = posNull++;
            for (let y = 0; y < cell.rowSpan; ++y) {
              let offY = c + y;
              if (this.cells2D.get(offX, offY) != null) {
                throw new Error("Bad colspan x=" + offX + ",y=" + offY);
              }
              this.cells2D.set(offX, offY, cell);
            }
          }
        }
      }
    }
  }
  let resolv;
  window.linkHelperCompleted = new Promise((resolve) => (resolv = resolve));
  document.addEventListener("DOMContentLoaded", () => {
    try {
      const instrTable = document.getElementById("instructions");
      const errorsDiv = document.getElementById("errors");
      window.zz = new TableHelper(instrTable);
      {
        const instrObject = {};
        const cells2D = window.zz.cells2D;
        for (let c = 0; c < cells2D.h; ) {
          const td = cells2D.get(4, c);
          const name = td.textContent;
          if (instrObject[name] == null) {
            instrObject[name] = c;
          } else {
            const str = `Name ${name} was encountered more than once at row ${instrObject[name]} and row ${c}`;
            const p = document.createElement("p");
            p.innerText = str;
            p.style.color = "red";
            errorsDiv.style.display = "";
            errorsDiv.appendChild(p);
            errorsDiv.appendChild(document.createElement("br"));
            console.warn(str);
          }
          const origHTML = td.innerHTML;
          td.innerHTML =
            '<a href="' +
            encodeURIComponent(name) +
            '.html">' +
            origHTML +
            "</a>";
          c += td.rowSpan;
        }
      }
    } finally {
      resolv?.();
    }
  });
}
