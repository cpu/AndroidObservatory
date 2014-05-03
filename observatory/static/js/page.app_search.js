(function AppSearch(){


  function initTables(){
    var config = {
      visible_items: 3,
      orientation: 'vertical',
      circular: 'yes',
      autoscroll: 'yes',
      interval: 2000,
      direction: 'up'
    };

    $('#recent-list').als(config);
    $('#random-list').als(config);
  }

  $(document).ready(function(){
    initTables();
  });
}());